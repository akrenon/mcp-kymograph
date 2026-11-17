"""The web interface in headless Chromium, with the network closed (CONTRACT section 10).

Runs inside the container of ``tests/test_web_headless.py`` (``--network none``, a read-only
root, ``python3 -I``, the standard library only): starts the interface from the source tree at
``/src`` against the data the spec names, starts Chromium and drives it over
``--remote-debugging-pipe``, visits every page and mode of the spec, and writes ``/out/report.json``
(and the screenshots, and the text of every page).

The spec is JSON on stdin::

    {"servers": {name: [web arguments]},
     "pages": [{"id", "server", "hash", "shot"}],
     "values": {NAME: hostile string}, "twins": {NAME: string that looks like one of them},
     "operate": {"store_diff": {...}, "fleet_compare": {...}, "signals": {...},
                 "review_history": {...}},
     "probes": [{"id", "server", "html"}],
     "leave": [address]}

``probes`` are pieces of markup written into the main element of a page that has rendered and
then observed like any page: they show that the pass sees what it must (a text beside child
elements, a value in a cell under a row with a ``details``, a ``value`` with an invisible
character, a link out). They are listed under ``probes`` in the report, apart from the pages.

``leave`` are addresses the check navigates to once everything else is done, from the page last
loaded: they show that a request to another origin is stopped. An address may begin with
``{name}``, the origin of the interface of that name (its port is known in the container only).
Each is listed under ``left`` in the report with ``paused`` (the request came to
``Fetch.requestPaused``) and ``failed`` (it was ended with ``Fetch.failRequest``), apart from
``outside_requests``, which holds what the pages asked for themselves. The request of an address is
a navigation of the main frame (``resourceType`` ``Document``, the ``frameId`` of the main frame)
to it after ``normalised``, the form Chromium writes it in (a host in capitals or not in ASCII,
the default port, no path, a character it percent-encodes, a fragment). One that comes after the
wait is over is answered like any other and still not counted under ``outside_requests``: the
check asked for it. Its address then stays ``paused: false``, as the report says what happened
within the wait. Two addresses that are the same after ``{name}`` and ``normalised`` are refused
before anything is visited: a request to the one could not be told from one to the other.

``--no-sandbox`` is accepted here and only here: Chromium's own sandbox needs privileges a
container without capabilities does not have, and everything it could protect is already shut
off — no network (``--network none``, and every request that is not to the interface's own origin
is failed and counted), a read-only root, data mounted read-only, and nothing of anyone else's in
the container.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import unicodedata
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote, urlsplit

OUT = Path("/out")
READY_SECONDS = 15
UNSAFE = {"Cc", "Cf", "Cs", "Co", "Cn"}
SIZES = ((1920, 1080), (1440, 900))
SERVER = re.compile(r"^\{(\w+)\}")
START = re.compile(r"(http://127\.0\.0\.1:(\d+)/\?token=\S+)")
TOKEN = re.compile(r"token=[A-Za-z0-9_-]+")
#: What the URL standard leaves as it is in a path and in the query of an ``http(s)`` address,
#: beside letters, digits and ``_.-~``: every other printable ASCII character but those of its
#: path (space, ``"#<>?`{}``) and its special-query (space, ``"#<>'``) percent-encode sets. ``%``
#: is among them: a ``%XX`` is not encoded twice.
PATH_SAFE = "!$%&'()*+,/:;=@[\\]^|"
QUERY_SAFE = "!$%&()*+,/:;=?@[\\]^`{|}"

CHROMIUM = [
    "chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
    "--remote-debugging-pipe", "--user-data-dir=/tmp/prof",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--disable-background-networking", "--disable-component-update", "--disable-default-apps",
    "--disable-sync", "--disable-breakpad", "--disable-domain-reliability",
    "--disable-client-side-phishing-detection", "--disable-extensions", "--metrics-recording-only",
    "--no-first-run", "--no-default-browser-check", "--password-store=basic",
    "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication",
    "about:blank",
]  # fmt: skip

SERVER_CODE = (
    "import sys; sys.path.insert(0, '/src'); from mcp_kymograph.cli import main; "
    "sys.exit(main(sys.argv[1:]))"
)


# -- the interface -------------------------------------------------------------------------------


def scrubbed(text: str) -> str:
    """The text with every ``token=<value>`` as ``token=<token>``: the start token opens the
    interface, and nothing that leaves the check may hold it: ``guarded`` filters the process's
    stderr, the files below ``/out`` are written through this."""
    return TOKEN.sub("token=<token>", text)


class Interface:
    """One ``kymograph web --port 0`` process, its start address read off its stderr."""

    def __init__(self, name: str, arguments: list[str]) -> None:
        self.name = name
        self.process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-I", "-c", SERVER_CODE, "web", "--port", "0", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env={"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ["PATH"]},  # noqa: S108
            text=True,
        )
        self.stderr: list[str] = []
        self.started = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()
        if not self.started.wait(30):
            raise SystemExit(f"{name}: no start line on stderr: {''.join(self.stderr)!r}")

    def _read(self) -> None:
        for line in self.process.stderr:
            found = START.search(line)
            if found and not self.started.is_set():
                # The start line is the one place the token stands; it is kept as start_url only.
                self.start_url, self.port = found.group(1), int(found.group(2))
                self.origin = f"http://127.0.0.1:{self.port}"
                self.started.set()
            else:
                self.stderr.append(scrubbed(line))

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()


# -- Chromium over the pipe ----------------------------------------------------------------------


def permitted(url: str, origin: str | None) -> bool:
    """Whether a request may go out: only to the origin of the interface whose page is loaded. The
    other interface is another origin, and so is anything else."""
    parts = urlsplit(url)
    return origin is not None and f"{parts.scheme}://{parts.netloc}" == origin


def normalised(url: str) -> str:
    """The address as Chromium asks for it: scheme and host in lower case, the host in IDNA
    (punycode), no default port (80 for ``http``, 443 for ``https``), ``/`` for an empty path, the
    path and the query percent-encoded as the URL standard says (a ``%XX`` stays as it is), no
    fragment. An address that does not split, or whose host IDNA refuses, stays as it is."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname or "", parts.port
        # An IPv6 host keeps its brackets; any other is asked for in IDNA.
        host = f"[{host}]" if ":" in host else host.encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return url
    scheme = parts.scheme.lower()
    if port is not None and (scheme, port) not in {("http", 80), ("https", 443)}:
        host = f"{host}:{port}"
    if "@" in parts.netloc:
        host = parts.netloc.rsplit("@", 1)[0] + "@" + host
    if not parts.netloc:
        query = f"?{parts.query}" if parts.query else ""
        return f"{scheme}:{parts.path}{query}"
    path = quote(parts.path or "/", safe=PATH_SAFE)
    query = f"?{quote(parts.query, safe=QUERY_SAFE)}" if parts.query else ""
    return f"{scheme}://{host}{path}{query}"


def navigation_to(params: dict, frame: str | None, addresses: set[str]) -> bool:
    """Whether a paused request is the check's own navigation: a document of the main frame, to
    one of the addresses of ``leave`` (normalised). A resource of the page at the same address, or
    a frame of it, is not."""
    return (
        params.get("resourceType") == "Document"
        and frame is not None
        and params.get("frameId") == frame
        and normalised(params["request"]["url"]) in addresses
    )


class Chromium:
    def __init__(self) -> None:
        #: The origin of the interface whose page is loaded; set before the page is asked for.
        self.origin: str | None = None
        pipes = [os.pipe() for _ in range(2)]
        # Lifted above 4, so that the dup2 in the child onto 3 and 4 cannot clobber one of them.
        r3, w3, r4, w4 = [os.dup(fd) for pair in pipes for fd in pair]
        for pair in pipes:
            for fd in pair:
                os.close(fd)
        # pipes[0] is (read, write) of the commands, pipes[1] of the answers: the child reads 3
        # and writes 4, this side writes w3 and reads r4. The pairs were flattened in that order.
        self.stderr = open("/tmp/chromium.stderr", "wb")  # noqa: SIM115, S108
        self.process = subprocess.Popen(  # noqa: S603
            CHROMIUM,
            pass_fds=(3, 4),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=self.stderr,
            preexec_fn=lambda: (os.dup2(r3, 3), os.dup2(w4, 4)),  # noqa: PLW1509
        )
        os.close(r3)
        os.close(w4)
        self.out = os.fdopen(w3, "wb", buffering=0)
        self.inp = os.fdopen(r4, "rb", buffering=0)
        self.write_lock = threading.Lock()
        self.next_id = 0
        self.waiting: dict[int, queue.Queue] = {}
        self.session: str | None = None
        self.page = ""
        self.outside: list[dict] = []
        self.console: list[dict] = []
        self.documents: list[dict] = []
        self.loaded = threading.Event()
        #: The id of the main frame, from ``Page.getFrameTree`` once the page is opened.
        self.frame: str | None = None
        #: The navigation of ``leave`` under way: its address, and what became of its request.
        self.leaving: dict | None = None
        #: Every address of ``leave`` asked for so far, normalised.
        self.left: set[str] = set()
        threading.Thread(target=self._read, daemon=True).start()

    def _send(self, method: str, params: dict | None, session: str | None) -> queue.Queue:
        with self.write_lock:
            self.next_id += 1
            ident = self.next_id
            answer: queue.Queue = queue.Queue()
            self.waiting[ident] = answer
            message = {"id": ident, "method": method, "params": params or {}}
            if session:
                message["sessionId"] = session
            self.out.write(json.dumps(message).encode() + b"\0")
        return answer

    def call(self, method: str, params: dict | None = None, *, browser: bool = False) -> dict:
        answer = self._send(method, params, None if browser else self.session)
        try:
            reply = answer.get(timeout=60)
        except queue.Empty:
            raise SystemExit(f"Chromium did not answer {method}") from None
        if "error" in reply:
            raise SystemExit(f"{method}: {reply['error']}")
        return reply.get("result", {})

    def _read(self) -> None:
        buffer = b""
        while True:
            chunk = self.inp.read(65536)
            if not chunk:
                return
            buffer += chunk
            while b"\0" in buffer:
                raw, buffer = buffer.split(b"\0", 1)
                message = json.loads(raw)
                if "id" in message:
                    waiter = self.waiting.pop(message["id"], None)
                    if waiter is not None:
                        waiter.put(message)
                else:
                    self._event(message)

    def _event(self, message: dict) -> None:
        method, params = message.get("method"), message.get("params", {})
        if method == "Fetch.requestPaused":
            url = params["request"]["url"]
            allowed = permitted(url, self.origin)
            if allowed:
                answer = self._send(
                    "Fetch.continueRequest", {"requestId": params["requestId"]}, self.session
                )
            else:
                answer = self._send(
                    "Fetch.failRequest",
                    {"requestId": params["requestId"], "errorReason": "BlockedByClient"},
                    self.session,
                )
            # A navigation of ``leave``: the check asked for it, the page did not, even after the
            # wait for it is over.
            ours = navigation_to(params, self.frame, self.left)
            leaving = self.leaving
            if (
                ours
                and leaving is not None
                and not leaving["paused"].is_set()
                and normalised(url) == leaving["url"]
            ):
                leaving.update(answer=answer, failing=not allowed)
                leaving["paused"].set()
            elif not allowed and not ours:
                self.outside.append({"page": self.page, "url": url})
        elif method == "Network.responseReceived" and params.get("type") == "Document":
            response = params["response"]
            self.documents.append(
                {
                    "path": urlsplit(response["url"]).path,
                    "status": response["status"],
                    "headers": {k.lower(): v for k, v in response["headers"].items()},
                }
            )
        elif method == "Page.loadEventFired":
            self.loaded.set()
        elif method == "Log.entryAdded":
            entry = params["entry"]
            if entry.get("level") == "error":
                self.console.append(
                    {
                        "page": self.page,
                        "via": "log",
                        "source": entry.get("source"),
                        "text": entry.get("text"),
                        "url": entry.get("url"),
                    }
                )
        elif method == "Runtime.exceptionThrown":
            details = params["exceptionDetails"]
            self.console.append(
                {
                    "page": self.page,
                    "via": "exception",
                    "text": details.get("text"),
                    "description": (details.get("exception") or {}).get("description"),
                }
            )
        elif method == "Runtime.consoleAPICalled" and params.get("type") == "error":
            texts = [str(a.get("value", a.get("description"))) for a in params["args"]]
            self.console.append({"page": self.page, "via": "console", "text": " ".join(texts)})

    def open(self) -> str:
        version = self.call("Browser.getVersion", browser=True)["product"]
        target = self.call("Target.createTarget", {"url": "about:blank"}, browser=True)["targetId"]
        self.session = self.call(
            "Target.attachToTarget", {"targetId": target, "flatten": True}, browser=True
        )["sessionId"]
        for method in ("Page.enable", "Runtime.enable", "Log.enable", "Network.enable"):
            self.call(method)
        self.frame = self.call("Page.getFrameTree")["frameTree"]["frame"]["id"]
        self.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
        return version

    def evaluate(self, expression: str):
        result = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": False},
        )
        if "exceptionDetails" in result:
            raise SystemExit(f"evaluate failed: {result['exceptionDetails']}")
        return result["result"].get("value")

    def navigate(self, url: str) -> None:
        self.loaded.clear()
        self.call("Page.navigate", {"url": url})
        if not self.loaded.wait(READY_SECONDS):
            raise SystemExit(f"no load event for {url}")

    def leave(self, url: str) -> dict:
        """Navigates to ``url``: whether its request came to ``Fetch.requestPaused`` within
        ``READY_SECONDS``, and whether it was failed there. An answer of Chromium that holds an
        error is raised. The address is kept: a request to it that comes later is not the page's."""
        address = normalised(url)
        leaving = {"url": address, "paused": threading.Event(), "answer": None, "failing": False}
        self.left.add(address)
        self.leaving = leaving
        try:
            self.call("Page.navigate", {"url": url})
            if not leaving["paused"].wait(READY_SECONDS):
                return {"paused": False, "failed": False}
            reply = leaving["answer"].get(timeout=60)
        finally:
            self.leaving = None
        if "error" in reply:
            raise SystemExit(f"the request to {url}: {reply['error']}")
        return {"paused": True, "failed": leaving["failing"]}

    def close(self) -> None:
        try:
            self._send("Browser.close", None, None)
            self.process.wait(10)
        except Exception:  # noqa: BLE001
            self.process.kill()


# -- what the page is asked ----------------------------------------------------------------------


def tokenised(text: str, *, block: bool = False, bracket: bool = False) -> str:
    """The text as the page writes it: a character of the categories the terminal does not
    show as a ``U+XXXX`` token (``[U+XXXX]`` where a node cannot go), a line feed kept in block
    text."""
    out = []
    for char in text:
        if unicodedata.category(char) in UNSAFE and not (block and char == "\n"):
            token = f"U+{ord(char):04X}"
            out.append(f"[{token}]" if bracket else token)
        else:
            out.append(char)
    return "".join(out)


def forms_of(text: str) -> dict[str, str]:
    """The ways the page may write a value: as text, as text inside a block, inside a JSON string
    of a payload shown whole (the quote, the backslash and the line and tab escapes JSON cannot do
    without; every other invisible character a token), as the label of an option, and as a
    sentence of the tool's own spells it (Python's escapes, ``repr``)."""
    escapes = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b"}
    escapes["\f"] = "\\f"
    in_json = "".join(escapes.get(char, char) for char in text)
    return {
        "text": tokenised(text),
        "block": tokenised(text, block=True),
        "json": tokenised(in_json, block=True),
        "option": tokenised(text, bracket=True),
        "spelled": repr(text)[1:-1],
    }


#: One evaluation over the rendered page: every element name of the body, every attribute (name and
#: value), every ``href`` and ``src`` of the whole document (``<head>`` too), the characters that
#: stand raw where a token should, and the hostile values with their place. The text is read per
#: text node: a node belongs to its parent element, and a ``span.cp`` token to the element that
#: holds it, so that a value with a token in it is one string again. The place is the header of
#: the column of the cell the value is in; else the ``dt`` of its ``dd``; else the ``aria-label``
#: of the nearest container; else the label of the ``role=note`` it is in (not when the label holds
#: the value itself); else the nearest heading before it in the same section. A label that
#: is empty is no place, and the search goes on to the next step. Nothing of another table row or
#: of the ``details`` of another row is looked at.
DOM_PASS = r"""
((forms) => {
  const UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u;
  const elements = {}, attributes = new Map(), found = new Map(), raw = [], references = [];
  const main = document.getElementById('main');
  const label = (n) => (n ? n.textContent.replace(/\s+/g, ' ').trim().slice(0, 120) : '');
  const named = (prefix, n) => { const text = label(n); return text === '' ? '' : prefix + text; };
  const HEADING = 'h1,h2,h3,h4';
  function termOf(dd) {
    let s = dd.previousElementSibling;
    while (s && !s.matches('dt')) s = s.previousElementSibling;
    return s;
  }
  function headOf(cell) {
    const table = cell.closest('table');
    const head = table && table.tHead && table.tHead.rows[0];
    if (!head) return null;
    let start = 0;
    for (let c = cell.parentElement.firstElementChild; c && c !== cell; c = c.nextElementSibling) start += c.colSpan || 1;
    let at = 0;
    for (const th of head.cells) { at += th.colSpan || 1; if (at > start) return th; }
    return null;
  }
  // A heading that stands in a row, a details or a section inside `s` is another row's, another
  // details' or another section's.
  const SECTION = 'section, article, aside, nav';
  const foreign = (x, s) => { const c = x.closest('tr, details, ' + SECTION); return c !== null && s.contains(c); };
  function headingBefore(el) {
    for (let node = el; node && node !== document.body; node = node.parentElement) {
      if (node.matches('td, th, tr')) continue;
      const own = node.matches('details') ? node.querySelector(':scope > summary') : null;
      if (own && !own.contains(el)) { const at = named('heading: ', own); if (at) return at; }
      for (let s = node.previousElementSibling; s; s = s.previousElementSibling) {
        const heads = s.matches(HEADING) ? [s] : Array.from(s.querySelectorAll(HEADING)).filter((x) => !foreign(x, s));
        for (let i = heads.length - 1; i >= 0; i--) { const at = named('heading: ', heads[i]); if (at) return at; }
      }
      // The section ends the climb: its own siblings belong to other sections.
      if (node.matches(SECTION + ', main')) break;
    }
    return '';
  }
  function nearest(el) {
    const cell = el.closest('td, th');
    if (cell) { const at = named('column: ', headOf(cell)); if (at) return at; }
    const dd = el.closest('dd');
    if (dd) { const at = named('dt: ', termOf(dd)); if (at) return at; }
    for (let node = el.parentElement; node && node !== document.body; node = node.parentElement) {
      const text = (node.getAttribute('aria-label') || '').trim();
      if (text) return 'aria-label: ' + text;
    }
    // A note names itself by its first `.key` or `.notice-kind`; a value is not its own place.
    const note = el.closest('[role=note]');
    const tag = note && note.querySelector('.key, .notice-kind');
    if (tag && !tag.contains(el)) { const at = named('note: ', tag); if (at) return at; }
    return headingBefore(el);
  }
  for (const el of document.documentElement.querySelectorAll('[href], [src]')) {
    for (const name of ['href', 'src']) {
      if (!el.hasAttribute(name)) continue;
      const value = el.getAttribute(name);
      references.push([el.localName, name, value.slice(0, 400), new URL(value, document.baseURI).origin]);
    }
  }
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  for (let el = walker.currentNode; el; el = walker.nextNode()) {
    const tag = el.localName;
    elements[tag] = (elements[tag] || 0) + 1;
    for (const a of el.attributes) {
      const value = a.value.slice(0, 400);
      attributes.set(tag + '\u0000' + a.name + '\u0000' + value, [tag, a.name, value]);
      if (UNSAFE.test(a.value)) raw.push(['attribute ' + a.name, value.slice(0, 80)]);
    }
  }
  // Every text node, in order: the raw characters of the node itself, and the text of its owner.
  const owners = new Map();
  const texts = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let node = texts.nextNode(); node; node = texts.nextNode()) {
    const parent = node.parentElement;
    if (parent.localName === 'script' || parent.localName === 'style') continue;
    const data = node.data;
    if (data === '') continue;
    const block = parent.closest('pre') !== null;
    // The white space between the elements of the markup (index.html, the templates) is no text
    // of the page. A line feed that is the whole text of an element holding no element is.
    const between = !block && /^[ \n]*$/.test(data) &&
      Array.from(parent.children).some((c) => !c.classList.contains('cp'));
    if (!between && UNSAFE.test(block ? data.replace(/\n/g, '') : data)) raw.push([block ? 'pre' : 'text', data.slice(0, 80)]);
    const token = parent.localName === 'span' && parent.classList.contains('cp') && parent.parentElement;
    const owner = token || parent;
    owners.set(owner, (owners.get(owner) || '') + data);
  }
  for (const [el, text] of owners) {
    for (const [name, byForm] of Object.entries(forms)) {
      for (const [form, needle] of Object.entries(byForm)) {
        if (needle === '' || !text.includes(needle)) continue;
        const place = nearest(el);
        const tag = el.localName;
        // Whether the value stands in a cell, and whether the header of its column has a label.
        const cell = el.closest('td, th');
        const headed = cell !== null && label(headOf(cell)) !== '';
        const key = [name, form, tag, place, cell !== null, headed].join('\u0000');
        const hit = found.get(key) || { name, form, element: tag, place, cell: cell !== null, headed, count: 0, whole: false };
        hit.count += 1;
        if (text === needle) hit.whole = true;
        found.set(key, hit);
      }
    }
  }
  if (UNSAFE.test(document.title)) raw.push(['title', document.title.slice(0, 80)]);
  return {
    ready_value: main.getAttribute('data-ready'),
    elements,
    attributes: Array.from(attributes.values()),
    references,
    found: Array.from(found.values()),
    raw,
    text: main.textContent,
    title: document.title,
    hash: location.hash,
    origin: location.origin,
  };
})(FORMS)
"""  # noqa: E501, S105


class Check:
    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.interfaces = {n: Interface(n, a) for n, a in spec["servers"].items()}
        self.chromium = Chromium()
        self.version = self.chromium.open()
        self.forms = {
            name: forms_of(text) for name, text in {**spec["values"], **spec["twins"]}.items()
        }
        self.current: str | None = None
        self.report: dict = {
            "pages": [], "operations": [], "probes": [], "screenshots": [], "left": [],
        }  # fmt: skip
        (OUT / "text").mkdir(exist_ok=True)
        (OUT / "shots").mkdir(exist_ok=True)

    # -- navigation and waiting ------------------------------------------------------------

    def ready(self) -> str | None:
        return self.chromium.evaluate(
            "(() => { const m = document.getElementById('main');"
            " return m ? m.getAttribute('data-ready') : null; })()"
        )

    def wait_for(self, before: str | None) -> str | None:
        """Waits until ``data-ready`` holds a value other than the one noted before. ``None``
        when it never does: the target did not render again."""
        deadline = time.monotonic() + READY_SECONDS
        while time.monotonic() < deadline:
            now = self.ready()
            if now is not None and now != before:
                return now
            time.sleep(0.05)
        return None

    def wait_until(self, condition: str) -> bool:
        """Waits until the expression is true: for a step that changes the page in place (a
        filter, a toggle) and draws nothing again, so that ``data-ready`` stays what it was."""
        deadline = time.monotonic() + READY_SECONDS
        while time.monotonic() < deadline:
            if self.chromium.evaluate(condition) is True:
                return True
            time.sleep(0.05)
        return False

    def state(self) -> str:
        """What a failure says: where the page stands, what it holds, what went wrong around it."""
        here = self.chromium.evaluate(
            "location.href + ' ' + document.readyState + ' '"
            " + document.body.innerHTML.slice(0, 600)"
        )
        problems = {
            "outside": self.chromium.outside,
            "console": self.chromium.console,
            "stderr": {n: "".join(i.stderr[-5:]) for n, i in self.interfaces.items()},
        }
        return f"{here}\n{json.dumps(problems, indent=1)}"

    def enter(self, server: str) -> None:
        """The token exchange: the start address, then ``/``."""
        if self.current == server:
            return
        interface = self.interfaces[server]
        self.chromium.origin = interface.origin
        self.chromium.navigate(interface.start_url)
        self.chromium.navigate(interface.origin + "/")
        self.current = server
        if self.wait_for(None) is None:
            raise SystemExit(f"{server}: the first view never became ready\n{self.state()}")

    def go(self, server: str, fragment: str) -> bool:
        self.enter(server)
        before = self.ready()
        if self.chromium.evaluate("location.hash") == fragment:
            # The same address again would change nothing: a document of its own.
            self.chromium.navigate("about:blank")
            self.chromium.navigate(self.interfaces[server].origin + "/" + fragment)
            return self.wait_for(None) is not None
        self.chromium.evaluate(f"location.hash = {json.dumps(fragment)}")
        return self.wait_for(before) is not None

    # -- the DOM pass ------------------------------------------------------------------------

    def observe(self, ident: str, rendered: bool) -> dict:
        """The DOM pass. ``rendered`` is what the wait for a new value said; ``ready_value`` is
        the raw ``data-ready`` of the page, and never stands in for it: a target that did not
        render again still holds the old one."""
        self.chromium.page = ident
        found = self.chromium.evaluate(DOM_PASS.replace("(FORMS)", f"({json.dumps(self.forms)})"))
        text = found.pop("text")
        (OUT / "text" / f"{ident.replace('/', '_')}.txt").write_text(
            scrubbed(text), encoding="utf-8"
        )
        found["text_chars"] = len(text)
        found["text_sha256"] = sha256(text.encode()).hexdigest()
        return {"id": ident, "rendered": rendered, **found}

    def shoot(self, ident: str) -> None:
        for width, height in SIZES:
            self.chromium.call(
                "Emulation.setDeviceMetricsOverride",
                {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
            )
            size = self.chromium.call("Page.getLayoutMetrics")["cssContentSize"]
            clip = {"x": 0, "y": 0, "width": width, "height": min(size["height"], 6000), "scale": 1}
            data = self.chromium.call(
                "Page.captureScreenshot",
                {"format": "png", "captureBeyondViewport": True, "clip": clip},
            )["data"]
            path = OUT / "shots" / f"{ident.replace('/', '_')}-{width}x{height}.png"
            path.write_bytes(base64.b64decode(data))
            self.report["screenshots"].append(str(path))
        self.chromium.call("Emulation.clearDeviceMetricsOverride")

    def visit(self, page: dict) -> None:
        rendered = self.go(page["server"], page["hash"])
        record = self.observe(page["id"], rendered)
        record["server"], record["requested"] = page["server"], page["hash"]
        self.report["pages"].append(record)
        if page.get("shot") and rendered:
            self.shoot(page["id"])

    # -- operations --------------------------------------------------------------------------

    def done(self, name: str, rendered: bool, **facts) -> None:
        record = self.observe(f"operate/{name}", rendered)
        record.update(facts)
        self.report["operations"].append({"name": name, **record})

    def click(self, selector: str) -> None:
        self.chromium.evaluate(f"document.querySelector({json.dumps(selector)}).click()")

    def pick(self, name: str, index: int) -> None:
        """A choice in a select as a person makes it: the value, then the events."""
        self.chromium.evaluate(
            f"(() => {{ const s = document.querySelector('select[name={name}]');"
            f" s.value = {json.dumps(str(index))};"
            " s.dispatchEvent(new Event('input', {bubbles: true}));"
            " s.dispatchEvent(new Event('change', {bubbles: true})); })()"
        )

    def compare(self, name: str, wanted: dict) -> None:
        """The pickers of the store diff and of the fleet comparison: the options by row index,
        then "Compare". What the address then holds is what the rows name."""
        opened = self.go(wanted["server"], wanted["hash"])
        before_ready = self.ready()
        self.pick("before", wanted["before_index"])
        self.pick("after", wanted["after_index"])
        chosen = self.chromium.evaluate(
            "['before', 'after'].map((n) => document.querySelector('select[name=' + n + ']').value)"
        )
        self.click("form.pick button[type=submit]")
        rendered = self.wait_for(before_ready) is not None
        address = self.chromium.evaluate("location.hash")
        shown = self.chromium.evaluate(
            "Array.from(document.querySelectorAll('#main .counter, #main .panel-title'))"
            ".map((e) => e.textContent.replace(/\\s+/g, ' ').trim()).slice(0, 40)"
        )
        self.done(name, opened and rendered, chosen=chosen, address=address, shown=shown)

    def signals(self, wanted: dict) -> None:
        opened = self.go(wanted["server"], wanted["hash"])
        count = self.chromium.evaluate("document.querySelectorAll('.filter button').length")
        # "All" is pressed when the page is built: it goes last, so that it has to change too.
        for index in [*range(1, count), 0]:
            button = f"document.querySelectorAll('.filter button')[{index}]"
            pressed_before = self.chromium.evaluate(f"{button}.getAttribute('aria-pressed')")
            self.click(f".filter button:nth-child({index + 1})")
            # The filter draws nothing again: the step is done when its button says it is pressed,
            # and it was not before.
            changed = (
                self.wait_until(f"{button}.getAttribute('aria-pressed') === 'true'")
                and pressed_before != "true"
            )
            state = self.chromium.evaluate(
                "(() => ({"
                " pressed: Array.from(document.querySelectorAll('.filter button'))"
                ".map((b) => b.getAttribute('aria-pressed')),"
                f" label: document.querySelectorAll('.filter button')[{index}].textContent,"
                " visible: Array.from(document.querySelectorAll('tr[data-reach]'))"
                ".filter((r) => !r.hidden && r.getClientRects().length > 0)"
                ".map((r) => r.getAttribute('data-reach')),"
                " reach: Array.from(document.querySelectorAll('tr[data-reach]'))"
                ".map((r) => r.getAttribute('data-reach')) }))()"
            )
            self.done(
                f"signals-filter-{index}",
                opened and changed,
                pressed_before=pressed_before,
                **state,
            )

    def review_history(self, wanted: dict) -> None:
        opened = self.go(wanted["server"], wanted["hash"])
        probe = (
            "(() => { const b = document.querySelector('button[aria-controls=review-history]');"
            " const box = document.getElementById('review-history');"
            " return b ? { expanded: b.getAttribute('aria-expanded'), label: b.textContent,"
            " hidden: box.hidden, height: box.getBoundingClientRect().height,"
            " state: b.parentElement.querySelector('span').textContent } : null; })()"
        )
        self.done("review-history-start", opened, **(self.chromium.evaluate(probe) or {}))
        for step, expanded in (("shown", "true"), ("hidden", "false")):
            self.click("button[aria-controls=review-history]")
            # The toggle draws nothing again: the step is done when the button says the new state.
            changed = self.wait_until(
                "document.querySelector('button[aria-controls=review-history]')"
                f".getAttribute('aria-expanded') === '{expanded}'"
            )
            self.done(f"review-history-{step}", changed, **(self.chromium.evaluate(probe) or {}))

    def strip(self, wanted: dict) -> None:
        """The strip of a run's findings tab, as a person uses it: what stands there when the
        address names no row; a row picked (the focus on its link, then the link) with the tables
        under the strip open; a second row picked; Back, twice; another tab of the run; and
        from there an address that names a row."""
        said = (
            "(() => { const a = document.activeElement;"
            " const text = (e) => e ? e.textContent.replace(/\\s+/g, ' ').trim() : null;"
            " const strip = document.querySelector('table.strip');"
            " const tables = document.querySelector('details.tables');"
            " const split = document.querySelector('.split');"
            " return { address: location.hash,"
            " selected: Array.from(document.querySelectorAll('a.pick[aria-current]'))"
            ".map((e) => [e.getAttribute('aria-current'), text(e)]),"
            " focus: a ? [a.tagName.toLowerCase(), a.className, text(a)] : null,"
            " eyebrow: text(document.querySelector('.sidepane .eyebrow')),"
            " heading: text(document.querySelector('.sidepane h2')),"
            " links: document.querySelectorAll('a.pick').length,"
            " note: strip ? text(strip.closest('.panel').querySelector('.panel-note')) : null,"
            " columns: strip ? Array.from(strip.querySelectorAll('th.msg a')).map(text) : [],"
            " bodies: strip ? Array.from(strip.tBodies).map((b) => Array.from(b.rows)"
            ".map((r) => ({ kind: r.className, name: text(r.cells[0]),"
            " head: [r.cells[0].tagName.toLowerCase(), r.cells[0].getAttribute('scope')],"
            " walk: text(r.querySelector('td.walk')),"
            " cells: Array.from(r.querySelectorAll('td.msg')).map((c) =>"
            " [text(c.querySelector('.vh')), text(c.querySelector('.n'))]) }))) : [],"
            " legend: Array.from(document.querySelectorAll('.legend .item')).map(text),"
            " tables_open: tables ? tables.open : null,"
            " tables_after_strip: !!(tables && split"
            " && (split.compareDocumentPosition(tables) & Node.DOCUMENT_POSITION_FOLLOWING)),"
            " tables: tables ? Array.from(tables.querySelectorAll('.panel')).map((p) =>"
            " [text(p.querySelector('.panel-title')),"
            " p.querySelectorAll('.panel-body > .tablewrap > table > tbody > tr,"
            " .panel-body > table > tbody > tr').length]) : [] }; })()"
        )

        def pick(which: str) -> bool:
            """Picks a row that is not the selected one: the first, or the last."""
            before = self.ready()
            self.chromium.evaluate(
                "(() => { const all = Array.from(document.querySelectorAll('a.pick'))"
                ".filter((e) => e.getAttribute('aria-current') !== 'true');"
                f" const a = all[{'0' if which == 'first' else 'all.length - 1'}];"
                " a.focus(); a.click(); })()"
            )
            return self.wait_for(before) is not None

        def back() -> bool:
            before = self.ready()
            self.chromium.evaluate("history.back()")
            return self.wait_for(before) is not None

        opened = self.go(wanted["server"], wanted["hash"])
        self.done("strip-start", opened, **self.chromium.evaluate(said))
        # What a reader opened in the place stays open when a row is picked.
        self.chromium.evaluate("document.querySelector('details.tables').open = true")
        self.done("strip-picked", pick("first"), **self.chromium.evaluate(said))
        self.done("strip-picked-again", pick("last"), **self.chromium.evaluate(said))
        self.done("strip-back", back(), **self.chromium.evaluate(said))
        self.done("strip-back-again", back(), **self.chromium.evaluate(said))
        before = self.ready()
        self.chromium.evaluate(
            "Array.from(document.querySelectorAll('nav.tabs a'))"
            ".filter((e) => e.getAttribute('aria-current') === null)[0].click()"
        )
        rendered = self.wait_for(before) is not None
        self.done("strip-left", rendered, **self.chromium.evaluate(said))
        # An address that names a row, reached from another place.
        arrived = self.go(wanted["server"], wanted["arrive"])
        self.done("strip-arrived", arrived, **self.chromium.evaluate(said))

    def probe(self, probe: dict) -> None:
        """Markup of the test written into the main element, and the pass over it."""
        self.enter(probe["server"])
        self.chromium.evaluate(
            f"document.getElementById('main').innerHTML = {json.dumps(probe['html'])}"
        )
        record = self.observe(f"probe/{probe['id']}", True)
        record["name"] = probe["id"]
        self.report["probes"].append(record)

    # -- leaving the origin ------------------------------------------------------------------

    def address(self, address: str) -> str:
        """The address with a leading ``{name}`` as the origin of that interface."""
        return SERVER.sub(lambda m: self.interfaces[m.group(1)].origin, address, count=1)

    def refuse_twins(self) -> None:
        """Ends the check when two addresses of ``leave`` are one after ``{name}`` and
        ``normalised``. An unknown name is compared as it is written."""
        seen: dict[str, str] = {}
        for address in self.spec.get("leave", []):
            try:
                key = normalised(self.address(address))
            except KeyError:
                key = address
            if key in seen:
                raise SystemExit(
                    f"leave: {seen[key]!r} and {address!r} are the same address ({key}):"
                    " a request to the one could not be told from one to the other"
                )
            seen[key] = address

    def leave(self, address: str) -> None:
        """A navigation away from the page last loaded. A fault on the way ends nothing: the
        address stands as not paused."""
        record = {"url": address, "paused": False, "failed": False}
        try:
            record["url"] = self.address(address)
            # The page is gone, whatever comes of it: the next ``enter`` loads it again.
            self.current = None
            record.update(self.chromium.leave(record["url"]))
        except (Exception, SystemExit):  # noqa: BLE001
            record.update(paused=False, failed=False)
        self.report["left"].append(record)

    # -- the run -----------------------------------------------------------------------------

    def run(self) -> None:
        self.refuse_twins()
        for page in self.spec["pages"]:
            self.visit(page)
        operate = self.spec.get("operate")
        if operate is not None:
            self.compare("store-diff-compare", operate["store_diff"])
            self.compare("fleet-compare", operate["fleet_compare"])
            self.signals(operate["signals"])
            self.review_history(operate["review_history"])
            if "strip" in operate:
                self.strip(operate["strip"])
        for probe in self.spec.get("probes", []):
            self.probe(probe)
        for address in self.spec.get("leave", []):
            self.leave(address)

    def failures(self) -> list[str]:
        """The targets that did not render again: a fault of the check, not a result."""
        records = [*self.report["pages"], *self.report["operations"]]
        return [r["id"] for r in records if not r["rendered"]]

    def write_report(self) -> None:
        self.report.update(
            chromium=self.version,
            origins=sorted(i.origin for i in self.interfaces.values()),
            outside_requests={
                "count": len(self.chromium.outside),
                "requests": self.chromium.outside,
            },
            documents=self.chromium.documents,
            console={"count": len(self.chromium.console), "entries": self.chromium.console},
            interface_stderr={n: "".join(i.stderr) for n, i in self.interfaces.items()},
        )
        text = scrubbed(json.dumps(self.report, indent=1))
        (OUT / "report.json").write_text(text, encoding="utf-8")

    def finish(self) -> None:
        self.write_report()
        self.chromium.close()
        for interface in self.interfaces.values():
            interface.stop()


def main() -> int:
    check = Check(json.load(sys.stdin))
    try:
        check.run()
    finally:
        check.finish()
    not_rendered = check.failures()
    if not_rendered:
        print(f"did not render again: {', '.join(not_rendered)}", file=sys.stderr)
        return 1
    return 0


def guarded(run) -> int:
    """The exit status of ``run``; what it says on stderr goes through ``scrubbed``: the text of a
    ``SystemExit``, the traceback of any other exception (status 1)."""
    try:
        return run()
    except SystemExit as stop:
        if stop.code is None:
            return 0
        if isinstance(stop.code, int):
            return stop.code
        print(scrubbed(str(stop.code)), file=sys.stderr)
        return 1
    except Exception:
        print(scrubbed(traceback.format_exc()), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(guarded(main))
