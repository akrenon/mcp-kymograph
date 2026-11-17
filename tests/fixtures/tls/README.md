# Test certificates

**Test-only keys.** Every private key in this directory is public, committed to a repository.
Never trust `ca.pem` or `foreign-ca.pem` anywhere but in this project's tests, and never use a
key from here for anything else.

They let the tests speak TLS to the loopback fixture server (`tests/fixtures/http_server.py`)
without a network: a test trusts `ca.pem` by setting `SSL_CERT_FILE` to it, which OpenSSL reads
when `ssl.create_default_context()` is made (http-transport.md 8.6).

| File | Issued by | Names | What a test uses it for |
|---|---|---|---|
| `ca.pem` | itself | — | the CA the tests trust |
| `localhost.pem`, `.key` | `ca.pem` | `localhost`, `127.0.0.1`, `::1` | a run that verifies |
| `other.pem`, `.key` | `ca.pem` | `other.test` | a name that does not match |
| `ip-127-0-0-2.pem`, `.key` | `ca.pem` | `127.0.0.2` | an address that reaches this machine and is not local to the gate |
| `foreign-ca.pem` | itself | — | a CA no test trusts |
| `foreign.pem`, `.key` | `foreign-ca.pem` | `localhost`, `127.0.0.1`, `::1` | an unknown CA |

EC P-256, SHA-256, valid from 2026-01-01T00:00:00Z for 100 years — the start back-dated, so a
machine whose clock is somewhat behind still takes them — with the extensions Python 3.13's default
`VERIFY_X509_STRICT` asks for. The CAs' private keys are not kept: nothing is issued after these.

Made once, with bash and OpenSSL 3.4 or later (for `-not_before` and `-not_after`), in an empty
directory:

```sh
from=20260101000000Z
until=21260101000000Z
ca() {  # file, common name
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
    -not_before "$from" -not_after "$until" -subj "/CN=$2" -keyout "$1.key" -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
}
leaf() {  # file, issuing CA's file, subjectAltName
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
    -subj "/CN=$1" -keyout "$1.key" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" \
    -set_serial "0x$(openssl rand -hex 16)" -not_before "$from" -not_after "$until" \
    -sha256 -out "$1.pem" \
    -extfile <(printf '%s\n' \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" \
      "subjectAltName=$3" \
      "subjectKeyIdentifier=hash" \
      "authorityKeyIdentifier=keyid:always")
  rm "$1.csr"
}
ca ca "mcp-kymograph test CA (test only)"
ca foreign-ca "mcp-kymograph foreign test CA (test only)"
leaf localhost ca "DNS:localhost,IP:127.0.0.1,IP:::1"
leaf other ca "DNS:other.test"
leaf ip-127-0-0-2 ca "IP:127.0.0.2"
leaf foreign foreign-ca "DNS:localhost,IP:127.0.0.1,IP:::1"
rm ca.key foreign-ca.key
```
