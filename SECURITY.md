# Security policy

## Reporting a vulnerability

Please report security issues by email to **security@akrenon.com**. Reports stay private
between you and the maintainers until a fix is available.

Please do not open a public issue, and please do not include customer data, real hostnames,
credentials, or recordings from an engagement in your report. A redacted reproduction is
enough.

We aim to acknowledge a report within 7 days.

## Scope

In scope: anything that causes Kymograph to leak credentials or recorded traffic, to
execute content that arrived over the wire, to write outside its output directory, to leave
orphaned processes behind, or to reach a target the user did not explicitly authorize.

Out of scope: vulnerabilities in the MCP servers you point Kymograph at. Finding those is
what the tool is for.

## Altering traffic requires an engagement

Kymograph can change messages in flight with a scenario, and a driven run's script can
call a server's tools, not only list them. Doing either to a system you were not engaged to
test is a different act from observing your own, so a scenario, or a script that calls tools,
against a target outside localhost is refused unless you confirm, with
`--engagement-confirmed`, that you hold an engagement. The run is refused before any process
starts. Pure observation needs no confirmation. The check fails closed: a target it does not
recognise as local is treated as non-local.

The flag is a statement you make, not a proof the tool can check. Over stdio the server is
always a local child process; there `--target` names the system you are testing and serves
only this check.

## Known properties, stated rather than implied

Recordings are written into a fresh per-run directory created with mode `0700`, and each
recording file with mode `0600`. If the parent output directory already exists with wider
permissions, Kymograph does not change them: the recordings inside stay protected, but the
run directory names remain visible to anyone who can list that directory. Kymograph does
not alter permissions on directories it did not create.

Recordings can have gaps. If observation cannot keep up with the traffic, events are
dropped rather than the connection being held up — the forwarding path is never allowed to
wait on the recording path. A gap is visible as a jump in the `seq` numbers, and the totals
are reported in the closing `run_finished` event. If writing fails outright, a
`recording_stopped` event marks the sequence number from which nothing further was
recorded, and forwarding continues.

## Supported versions

Only the newest version is supported while the project is pre-1.0.
