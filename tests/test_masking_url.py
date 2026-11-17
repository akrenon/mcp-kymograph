"""The userinfo of a URL in the text rules (src/mcp_kymograph/masking.py, ``_UrlUserinfo``,
``_DecodedUrlUserinfo``, ``_GoMysqlDsn``): everything between ``scheme://`` and the last ``@``
before the end of the authority goes, in any scheme, the user name included; so does the same
in a URL written in part or whole in an encoded form (percent-encoded once or twice, JSON
escapes, HTML entities, full-width), and what stands in front of ``@tcp(``, ``@unix(`` or any
other network in a DSN of Go's MySQL driver. Scheme, host, port, path and query stay. Text
without ``://`` stays as it is (``git@github.com:o/r.git``, ``mailto:a@b``). One URL counts once.
"""

from __future__ import annotations

import time
import urllib.parse

import pytest

from mcp_kymograph.masking import PLACEHOLDER, Masker, url_reach, withheld_path, withhold_url_path


def _made_up(*parts: str) -> str:
    """Fake credentials are put together when the test runs, never written whole."""
    return "".join(parts)


PW = _made_up("s3cr", "etValue", "123")
USER = _made_up("read", "er77")
GHP = _made_up("gh", "p_", "Ab1" * 12)
HEX40 = _made_up("0123456789", "abcdef" * 5)
TOKEN = _made_up("tok", "en-Xy7", "Qw9Lm2")
RAW_LEFT = _made_up("Sh0r", "tPart")
RAW_RIGHT = _made_up("RawPa", "rt9")
PCT_LEFT = _made_up("Zq81", "xLeft")
PCT_RIGHT = _made_up("Wv93", "kRight")

#: (url, what must be gone, what must stay)
FORMS = {
    "postgres": (f"postgres://{USER}:{PW}@db.internal:5432/app", [USER, PW],
                 ["postgres://", "@db.internal:5432/app"]),
    "postgresql": (f"postgresql://{USER}:{PW}@postgres:5432/db", [USER, PW],
                   ["postgresql://", "@postgres:5432/db"]),
    "postgresql, empty host": (f"postgresql://{USER}:{PW}@/db?host=/run/pg", [USER, PW],
                               ["postgresql://", "@/db?host=/run/pg"]),
    "jdbc:postgresql": (f"jdbc:postgresql://{USER}:{PW}@pg.internal:5432/app", [USER, PW],
                        ["jdbc:postgresql://", "@pg.internal:5432/app"]),
    "mysql": (f"mysql://{USER}:{PW}@mysql.internal:3306/app", [USER, PW],
              ["mysql://", "@mysql.internal:3306/app"]),
    "mysqlx": (f"mysqlx://{USER}:{PW}@mysql.internal:33060/app", [USER, PW],
               ["mysqlx://", "@mysql.internal:33060/app"]),
    "jdbc:mysql": (f"jdbc:mysql://{USER}:{PW}@mysql.internal:3306/app", [USER, PW],
                   ["jdbc:mysql://", "@mysql.internal:3306/app"]),
    "go dsn tcp": (f"{USER}:{PW}@tcp(mysql.internal:3306)/app", [USER, PW],
                   ["@tcp(mysql.internal:3306)/app"]),
    "go dsn unix": (f"{USER}:{PW}@unix(/run/mysqld/mysqld.sock)/app", [USER, PW],
                    ["@unix(/run/mysqld/mysqld.sock)/app"]),
    "redis, no user": (f"redis://:{PW}@cache.internal:6379/0", [PW],
                       ["redis://", "@cache.internal:6379/0"]),
    "redis": (f"redis://{USER}:{PW}@cache.internal", [USER, PW],
              ["redis://", "@cache.internal"]),
    "rediss": (f"rediss://{USER}:{PW}@cache.internal:6380/1", [USER, PW],
               ["rediss://", "@cache.internal:6380/1"]),
    "mongodb, hosts": (
        f"mongodb://{USER}:{PW}@h1.internal:27017,h2.internal:27017/app?replicaSet=rs0",
        [USER, PW],
        ["mongodb://", "@h1.internal:27017,h2.internal:27017/app?replicaSet=rs0"],
    ),
    "mongodb+srv": (f"mongodb+srv://{USER}:{PW}@cluster0.example.net/app", [USER, PW],
                    ["mongodb+srv://", "@cluster0.example.net/app"]),
    "ghp as user": (f"https://{GHP}@github.com/o/r.git", [GHP],
                    ["https://", "@github.com/o/r.git"]),
    "x-access-token": (f"https://x-access-token:{TOKEN}@github.com/o/r", ["x-access-token", TOKEN],
                       ["https://", "@github.com/o/r"]),
    "oauth2": (f"https://oauth2:{TOKEN}@gitlab.example/o/r.git", ["oauth2", TOKEN],
               ["https://", "@gitlab.example/o/r.git"]),
    "40 hex as user": (f"https://{HEX40}@github.com/o/r", [HEX40],
                       ["https://", "@github.com/o/r"]),
    "percent-encoded userinfo": (f"https://{USER}%3A{PCT_LEFT}%40{PCT_RIGHT}@h.example/x",
                                 [USER, PCT_LEFT, PCT_RIGHT], ["https://", "@h.example/x"]),
    "raw @ in the password": (f"https://{USER}:{RAW_LEFT}@{RAW_RIGHT}@h.example/x",
                              [USER, RAW_LEFT, RAW_RIGHT], ["https://", "@h.example/x"]),
    "percent-encoded whole": (
        f"https%3A%2F%2F{USER}%3A{PW}%40h.example%2Fx",
        [USER, PW],
        ["https%3A%2F%2F", "%40h.example%2Fx"],
    ),
    "percent-encoded whole, lower case": (
        f"https%3a%2f%2f{USER}%3a{PW}%40h.example%2fx",
        [USER, PW],
        ["https%3a%2f%2f", "%40h.example%2fx"],
    ),
}  # fmt: skip

#: What must stay in an argument, for the four forms that have no host and port the run could
#: list, or a scheme with no default port to complete one (``jdbc:``, an empty host, a list of
#: hosts): an argument withholds their path (``/db``, ``/app``), so the parts stand around it.
#: Every other form keeps what ``FORMS`` lists.
ARGV_PARTS = {
    "postgresql, empty host": ["postgresql://", "@", "?host=/run/pg"],
    "jdbc:postgresql": ["jdbc:postgresql://", "@pg.internal:5432"],
    "jdbc:mysql": ["jdbc:mysql://", "@mysql.internal:3306"],
    "mongodb, hosts": ["mongodb://", "@h1.internal:27017,h2.internal:27017", "?replicaSet=rs0"],
}


def _gone(result: str, secrets: list[str]) -> None:
    for secret in secrets:
        assert secret not in result
        assert urllib.parse.quote(secret, safe="") not in result


def _hits(url: str) -> int:
    """One URL counts once. ``x-access-token:<t>`` holds the scheme ``Token`` and a bare value
    after its colon: the scheme rule, which runs first, counts that one, and the URL rule then
    takes the rest of the userinfo, with the placeholder in it, and does not count it again."""
    return 1


def _pair(url: str) -> list[tuple[str, int | None, str]]:
    """What makes the URL's path verbatim: its host, effective port and path. Nothing for text
    that has no host to take apart; its path, if any, is withheld."""
    reach = url_reach(url)
    return [] if reach is None else [(*reach, urllib.parse.urlsplit(url).path)]


def _kept(result: str, parts: list[str]) -> None:
    for part in parts:
        assert part in result
    assert PLACEHOLDER in result


@pytest.mark.parametrize(
    ("name", "url", "secrets"), [(n, f[0], f[1]) for n, f in FORMS.items()], ids=FORMS.keys()
)
def test_argv_positional(name, url, secrets):
    parts = ARGV_PARTS.get(name, FORMS[name][2])
    masked, hits = Masker().mask_argv(["/usr/bin/node", url], verbatim_paths=_pair(url))
    assert masked[0] == "node"
    _gone(masked[1], secrets)
    _kept(masked[1], parts)
    assert hits == _hits(url)


@pytest.mark.parametrize(
    ("name", "url", "secrets"), [(n, f[0], f[1]) for n, f in FORMS.items()], ids=FORMS.keys()
)
def test_argv_flag_value(name, url, secrets):
    parts = ARGV_PARTS.get(name, FORMS[name][2])
    masked, hits = Masker().mask_argv(["server", "--url", url], verbatim_paths=_pair(url))
    assert masked[1] == "--url"
    _gone(masked[2], secrets)
    _kept(masked[2], parts)
    assert hits == _hits(url)


@pytest.mark.parametrize("frame", ["connect to {} now", "url = '{}'", 'dsn: "{}"', "use:\n{}\nok"])
@pytest.mark.parametrize(("url", "secrets", "parts"), FORMS.values(), ids=FORMS.keys())
def test_text(url, secrets, parts, frame):
    text = frame.format(url)
    masked, hits = Masker().mask_text(text)
    _gone(masked, secrets)
    _kept(masked, parts)
    assert hits == _hits(url)
    head, tail = frame.split("{}")
    if "@tcp(" in url or "@unix(" in url:
        head = head.rstrip("'\"")  # a quote in front of a Go DSN may be the password's; it goes
    assert masked.startswith(head) and masked.endswith(tail)


@pytest.mark.parametrize(("url", "secrets", "parts"), FORMS.values(), ids=FORMS.keys())
def test_json(url, secrets, parts):
    document = {"config": {"servers": [{"name": "db"}, f"use {url}"]}, "n": 1}
    masked, paths = Masker().mask_json(document)
    assert paths == ["config.servers[1]"]
    _gone(masked["config"]["servers"][1], secrets)
    _kept(masked["config"]["servers"][1], parts)
    assert masked["config"]["servers"][0] == {"name": "db"} and masked["n"] == 1


@pytest.mark.parametrize(
    ("text", "masked", "hits"),
    [
        (
            "postgresql://reader:pw@postgres:5432/db",
            f"postgresql://{PLACEHOLDER}@postgres:5432/db",
            1,
        ),
        ("ssh://git@host/o/r.git", f"ssh://{PLACEHOLDER}@host/o/r.git", 1),
        ("redis://:pw@h", f"redis://{PLACEHOLDER}@h", 1),
        # the last "@" of the authority, not the first
        ("https://u:p@ss@h/x@y", f"https://{PLACEHOLDER}@h/x@y", 1),
        ("u:p@ss@tcp(h)/db", f"{PLACEHOLDER}@tcp(h)/db", 1),
        ("x=https%3A%2F%2Fu%3Ap%40ss%40h%2Fx", f"x=https%3A%2F%2F{PLACEHOLDER}%40h%2Fx", 1),
        ("next=https%3A%2F%2Fu%3Ap%40host%2Fx", f"next=https%3A%2F%2F{PLACEHOLDER}%40host%2Fx", 1),
        # each URL counts once
        ("a://u:p@h b://v:q@i", f"a://{PLACEHOLDER}@h b://{PLACEHOLDER}@i", 2),
        ("a://u:p@h/b://v:q@i", f"a://{PLACEHOLDER}@h/b://{PLACEHOLDER}@i", 2),
        # a "://" in the userinfo starts no URL of its own: all of it goes, to the last "@"
        ("a://x:b://u:p@h", f"a://{PLACEHOLDER}@h", 1),
        ("postgresql://u:pa://ss@h/db", f"postgresql://{PLACEHOLDER}@h/db", 1),
        ("a://reader:pw://v:q@i", f"a://{PLACEHOLDER}@i", 1),
        # a "://" with no scheme in front starts no URL, and hides none behind it
        ("1+://b://u:p@h", f"1+://b://{PLACEHOLDER}@h", 1),
        # two anchors with no separator between them are one span
        ("u:p@tcp(a)/x,v:q@tcp(b)/y", f"{PLACEHOLDER}@tcp(b)/y", 1),
        # a Go DSN behind a scheme keeps it, and the URL is not counted twice
        ("mysql://u:p@tcp(h:3306)/db", f"mysql://{PLACEHOLDER}@tcp(h:3306)/db", 1),
        # empty userinfo holds nothing
        ("https://@h/", "https://@h/", 0),
        ("@tcp(h)/db", "@tcp(h)/db", 0),
        # what the scheme rule leaves in a userinfo does not end it: nothing of it stays, and
        # the URL, replaced in already, is not counted again
        ("https://x-token:abcdefgh9@h/", f"https://{PLACEHOLDER}@h/", 1),
        ("dsn=x-token:abcdefgh9@tcp(h)/db", f"{PLACEHOLDER}@tcp(h)/db", 1),
        ("dsn=x-token:abcdefgh9@tcp(h)/db ok", f"{PLACEHOLDER}@tcp(h)/db ok", 1),
        (f"https://x-access-token:{TOKEN}@github.com/", f"https://{PLACEHOLDER}@github.com/", 1),
        # a raw "@" in a URL percent-encoded otherwise
        ("x=https%3A%2F%2Fu%3Ap@h%2Fx", f"x=https%3A%2F%2F{PLACEHOLDER}@h%2Fx", 1),
        ("x=https%3A%2F%2Fu%3Ap%40ss@h%2Fx", f"x=https%3A%2F%2F{PLACEHOLDER}@h%2Fx", 1),
        # an encoded "@" behind a plain one: the rest of the password goes too, counted once
        ("https://a@b&#64;c/x", f"https://{PLACEHOLDER}&#64;c/x", 1),
    ],
    ids=range(24),
)
def test_exact(text, masked, hits):
    assert Masker().mask_text(text) == (masked, hits)


@pytest.mark.parametrize("end", ["/", "?", "#", " ", "\t", "\n", '"', "'", "`", "<", ">"])
def test_each_end_of_the_authority(end):
    """An ``@`` behind the end of the authority is not the userinfo's."""
    # A host without a dot: with one, the text is an address, which the personal-data rules
    # replace (test_personal_data.py).
    text = f"https://h.example{end}a@b"
    assert Masker().mask_text(text) == (text, 0)
    assert Masker().mask_text(f"https://u:p@h{end}x") == (f"https://{PLACEHOLDER}@h{end}x", 1)


@pytest.mark.parametrize(
    "end",
    [
        "%2F", "%2f", "%3F", "%3f", "%23", "%252F", "\\/", "&sol;", "&#47;", "&#x2F;", "／",
        "/", "?", "#", " ", '"', "'", "`", "<", ">",
    ],
)  # fmt: skip
def test_each_end_of_an_encoded_authority(end):
    text = f"x=https%3A%2F%2Fh.example{end}a%40b"
    assert Masker().mask_text(text) == (text, 0)
    masked = f"x=https%3A%2F%2F{PLACEHOLDER}%40h{end}y"
    assert Masker().mask_text(f"x=https%3A%2F%2Fu%3Ap%40h{end}y") == (masked, 1)


def test_an_ampersand_does_not_end_an_encoded_authority():
    """The grammar is the plain URL's, and ``&`` may stand in a userinfo: what is in front of
    the last ``@`` goes, fail closed."""
    text = "x=https%3A%2F%2Fh.example&a%40b"
    assert Masker().mask_text(text) == (f"x=https%3A%2F%2F{PLACEHOLDER}%40b", 1)


@pytest.mark.parametrize("cut", [" ", "\t", "\n"])
def test_each_cut_of_a_go_dsn(cut):
    text = f"keep{cut}u:p@tcp(h:3306)/db"
    assert Masker().mask_text(text) == (f"keep{cut}{PLACEHOLDER}@tcp(h:3306)/db", 1)
    text = f"keep{cut}u:p@unix(/run/s)/db"
    assert Masker().mask_text(text) == (f"keep{cut}{PLACEHOLDER}@unix(/run/s)/db", 1)


@pytest.mark.parametrize("mark", ['"', "'", "`", "=", ":", "/", ":pa://"])
def test_what_goes_with_a_go_dsn(mark):
    """A password in a DSN is not encoded: none of these cuts it, and what stands in front of
    them back to white space goes with it."""
    text = f"keep {USER}{mark}{PW}@tcp(h:3306)/db"
    assert Masker().mask_text(text) == (f"keep {PLACEHOLDER}@tcp(h:3306)/db", 1)


NETWORKS = ["tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram", "unixpacket"]


@pytest.mark.parametrize("network", NETWORKS)
def test_each_network_of_a_go_dsn(network):
    text = f"{USER}:{PW}@{network}(h:3306)/db"
    masked, hits = Masker().mask_text(text)
    assert (masked, hits) == (f"{PLACEHOLDER}@{network}(h:3306)/db", 1)
    masked, hits = Masker().mask_argv(["node", f"--dsn={USER}:{PW}@{network}(h)/db"])
    _gone(masked[1], [USER, PW])
    assert (masked, hits) == (["node", f"{PLACEHOLDER}@{network}(h)/db"], 1)


#: Go DSNs from the reviews: (text, what it becomes).
GO_DSNS = {
    ":// in the password": (f"{USER}:pa://{PW}@tcp(h:3306)/db", f"{PLACEHOLDER}@tcp(h:3306)/db"),
    "scheme and :// in the password": (
        f"mysql://{USER}:pa://{PW}@tcp(h)/db",
        f"mysql://{PLACEHOLDER}@tcp(h)/db",
    ),
    "base64 padding": (f"{USER}:YWJjZA==@tcp(h)/db", f"{PLACEHOLDER}@tcp(h)/db"),
    "dsn=": (f"dsn={USER}:{PW}@tcp(h)/db", f"{PLACEHOLDER}@tcp(h)/db"),
    "quoted, quote in the password": (
        f'dsn = "{USER}:{PW}\'x@tcp(h)/db"',
        f'dsn = {PLACEHOLDER}@tcp(h)/db"',
    ),
    "tcp4 as argv": (f"--dsn={USER}:{PW}@tcp4(h)/db", f"{PLACEHOLDER}@tcp4(h)/db"),
}


@pytest.mark.parametrize(("text", "masked"), GO_DSNS.values(), ids=GO_DSNS.keys())
def test_go_dsns_from_the_reviews(text, masked):
    result, hits = Masker().mask_text(text)
    _gone(result, [USER, PW, "pa", "YWJjZA"])
    assert (result, hits) == (masked, 1)
    result, hits = Masker().mask_argv(["server", text])
    # ``pa://`` is a scheme, so an argument withholds the path ``/db`` of the DSN behind it; the
    # words of that stand-in hold "pa", which is not the password's.
    withheld = withheld_path("/db")
    _gone(result[1].replace(withheld, ""), [USER, PW, "pa", "YWJjZA"])
    assert (result[1], hits) == (masked.replace("/db", withheld) if "pa://" in text else masked, 1)


#: URLs in an encoded form, from the reviews: (text, what it becomes[, path withheld]). Two have
#: a plain ``https://`` the path rule meets, a URL anywhere in an argument being one (``x=`` before
#: it does not hide it): the full-width one, and the one behind ``x=`` whose ``@`` is written
#: ``\u0040``. Neither has an authority that can be taken apart into a host and a port (the
#: full-width delimiters normalise into ``:`` and ``@``; the escape keeps the ``@`` from being
#: one), so there is no pair to keep the path under and it is withheld. In every other case the
#: ``://`` or the ``/`` is written in an encoded form, or there is no path, so no URL is met and
#: the text stays as written.
ENCODED = {
    "%3A//": (f"next=https%3A//{USER}:{PW}@h/x", f"next=https%3A//{PLACEHOLDER}@h/x"),
    ":%2F%2F": (f"next=https:%2F%2F{USER}:{PW}@h", f"next=https:%2F%2F{PLACEHOLDER}@h"),
    "json \\/": (
        f'"postgresql:\\/\\/{USER}:{PW}@h\\/db"',
        f'"postgresql:\\/\\/{PLACEHOLDER}@h\\/db"',
    ),
    "&#64;": (f"https://{USER}:{PW}&#64;h/x", f"https://{PLACEHOLDER}&#64;h/x"),
    "&#x40;": (f"https://{USER}:{PW}&#x40;h/x", f"https://{PLACEHOLDER}&#x40;h/x"),
    "&commat; &colon; &sol;": (
        f"https&colon;&sol;&sol;{USER}&colon;{PW}&commat;h/x",
        f"https&colon;&sol;&sol;{PLACEHOLDER}&commat;h/x",
    ),
    "\\u0040": (f"x=https://{USER}:{PW}\\u0040h/x", f"x=https://{PLACEHOLDER}\\u0040h/x", True),
    "\\u003A": (f"https\\u003A//{USER}:{PW}@h/x", f"https\\u003A//{PLACEHOLDER}@h/x"),
    "encoded twice": (
        f"https%253A%252F%252F{USER}%253A{PW}%2540h",
        f"https%253A%252F%252F{PLACEHOLDER}%2540h",
    ),
    "full-width": (f"https://{USER}：{PW}＠h/x", f"https://{PLACEHOLDER}＠h/x", True),
    "full-width solidus": (
        f"https:／／{USER}:{PW}@h/x",
        f"https:／／{PLACEHOLDER}@h/x",
    ),
    "quote, the standard form": (
        urllib.parse.quote(f"https://{USER}:{PW}@h/x"),
        f"https%3A//{PLACEHOLDER}%40h/x",
    ),
}


@pytest.mark.parametrize(
    ("text", "masked", "withheld"),
    [(*case, *(False,) * (3 - len(case))) for case in ENCODED.values()],
    ids=ENCODED.keys(),
)
def test_encoded_urls_from_the_reviews(text, masked, withheld):
    result, hits = Masker().mask_text(text)
    _gone(result, [USER, PW])
    assert (result, hits) == (masked, 1)
    result, hits = Masker().mask_argv(["server", text], verbatim_paths=_pair(text))
    # A URL with a path that cannot be taken apart into a host and a port (a port that is not
    # one, characters that normalise into delimiters) has no pair to keep its path under, so
    # the path is withheld.
    kept = masked.replace("/x", withheld_path("/x")) if withheld else masked
    assert (result[1], hits) == (kept, 1)
    document, paths = Masker().mask_json({"url": text})
    assert (document, paths) == ({"url": masked}, ["url"])


def test_a_path_the_run_allows_stays_behind_x_and_any_other_is_withheld():
    """The reason for the withholding, not only its result: a URL behind ``x=`` is met, and what
    keeps its path is a pair the run declared for that host, port and path."""
    text = "x=https://h.example/p/q"

    kept, hits = Masker().mask_argv(["s", text], verbatim_paths=[("h.example", 443, "/p/q")])
    assert (kept, hits) == (["s", text], 0)
    other, _ = Masker().mask_argv(["s", text], verbatim_paths=[("h.example", 443, "/other")])
    assert other == ["s", "x=https://h.example" + withheld_path("/p/q")]
    elsewhere, _ = Masker().mask_argv(["s", text], verbatim_paths=[("g.example", 443, "/p/q")])
    assert elsewhere == other


@pytest.mark.parametrize(
    "text",
    [
        "x=https%3A%2F%2Fh%2Fp&#64;x",
        "https://h/p\\u0040x",
        "https://h／p＠x",
        "&#64;&#x40;\\u0040%40%2540",
        "%3A%2F%2F%40h",
        "https\\u003A//\\u0040h",
        "x=%C3%A9 \\u00e9 &#233; &#xE9;",  # encoded, but not ASCII: read as written
    ],
)
def test_what_stays_encoded(text):
    assert Masker().mask_text(text) == (text, 0)


@pytest.mark.parametrize(
    "text",
    [
        "git@github.com:o/r.git",
        "mailto:a@host",  # an address with a dot in its host is replaced as one
        "write to a@host",
        "https://h.example/p?q=1",
        "https://h/p@x",
        "https://h/?a=b@c",
        "https://maps.example.org/@52.5,13.4,12z/data=!3m1",
        "1+://u:p@h",  # no letter, no scheme
        "u:p@tcp7(h)/db",  # no network of the driver
        "u:p@tcp (h)/db",
        "x=https%3A%2F%2Fh%2Fp%40x",
        "x=https%3A%2F%2F%40h%2Fp",
    ],
)
def test_what_stays(text):
    assert Masker().mask_text(text) == (text, 0)


HOSTILE = {
    "many :// without @": lambda n: "a://" * (n // 4),
    "many :// behind digits": lambda n: "1://" * (n // 4),
    "long password without end": lambda n: "a://u:" + "p" * n,
    "long password, then @": lambda n: "a://u:" + "p" * n + "@h",
    "many @": lambda n: "a://" + "@" * n,
    "many @ without ://": lambda n: "@" * n,
    "many encoded ://": lambda n: "%3A%2F%2F" * (n // 9),
    "many encoded :// and %40": lambda n: "%3a%2f%2f%40" * (n // 12),
    "encoded password without end": lambda n: "%3A%2F%2F" + "p" * n,
    "many @tcp( without separators": lambda n: "@tcp(" * (n // 5),
    "many u@tcp( without separators": lambda n: "u:p@tcp(" * (n // 8),
    "long run, then @tcp(": lambda n: "x" * n + "@tcp(",
    "long run without white space": lambda n: "a" * n,
    "long digit run, then ://": lambda n: "1" * n + "://u:p@h",
    "many separators and anchors": lambda n: "=u@unix(" * (n // 8),
    "many placeholders in an authority": lambda n: "a://" + f" {PLACEHOLDER}" * (n // 15),
    "many placeholders before @tcp(": lambda n: f" {PLACEHOLDER}" * (n // 15) + "@tcp(",
    "many :// in one authority": lambda n: "a://" + "u:p://" * (n // 6),
    "many :// in one authority, then @": lambda n: "a://" + "u:p://" * (n // 6) + "@h",
    "many :// behind a scheme without a letter": lambda n: "1://a" * (n // 5),
    "many encoded @ in one authority": lambda n: "a://" + "&#64;" * (n // 5),
    "many encoded :// without @": lambda n: "a%3A//" * (n // 6),
    "many twice-encoded ://": lambda n: "a%253A%252F%252F" * (n // 16),
    "many json-escaped ://": lambda n: "a:\\/\\/" * (n // 7),
    "many \\u escapes": lambda n: "\\u0040" * (n // 6),
    "many entities": lambda n: "&#x40;&commat;&#58;" * (n // 19),
    "many open entities": lambda n: "&#" + "1" * n,
    "many full-width forms": lambda n: "a：／／＠" * (n // 5),
    "many encoded pieces out of ASCII": lambda n: "%C3%A9\\u00e9&#233;" * (n // 18),
    "many encoded @ behind a plain ://": lambda n: "a://u" + "%40" * (n // 3),
    "many anchors behind a scheme": lambda n: f"m://{PLACEHOLDER}@tcp(" * (n // 23),
    "many networks": lambda n: "u:p@unixpacket(@udp6(@tcp4(" * (n // 27),
    "long scheme run before each anchor": lambda n: "a" * (n // 2) + f"://{PLACEHOLDER}@tcp(",
}


@pytest.mark.parametrize("build", HOSTILE.values(), ids=HOSTILE.keys())
def test_hostile_input_is_masked_in_linear_time(build):
    """Four times the input must cost about four times the time, not sixteen. The best of
    three runs is compared, and the bound is generous so that a slow machine does not fail it."""
    masker = Masker()

    def best(text: str) -> float:
        runs = []
        for _ in range(3):
            started = time.perf_counter()
            masker.mask_text(text)
            runs.append(time.perf_counter() - started)
        return min(runs)

    small = best(build(200_000))
    large = best(build(800_000))
    assert large < 12 * max(small, 0.005)


@pytest.mark.parametrize("build", [lambda n: "a" * n, lambda n: "a:" * n], ids=["a", "a:"])
def test_withholding_a_path_over_200_kb_ends_quickly(build):
    started = time.perf_counter()
    withhold_url_path(build(200_000))
    assert time.perf_counter() - started < 2
