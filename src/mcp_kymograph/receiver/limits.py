"""Every fixed limit of the receiver, by name. The values are listed in ``docs/receiver.md``."""

#: The service listens here and nowhere else; a TLS proxy in front terminates 443.
BIND_ADDRESS = "127.0.0.1"
#: Only a connection from this address is believed when it names a scheme or a sender.
TRUSTED_PROXY = "127.0.0.1"

#: Request line plus headers, in bytes. Over this, the request is counted and not recorded.
MAX_HEADER_BYTES = 16 * 1024
#: Bytes of body read and hashed. Past this the rest is discarded and the entry says so.
MAX_BODY_BYTES = 1024 * 1024
#: Wall-clock budget for one connection, from accept to response.
CONNECTION_TIMEOUT_SECONDS = 10.0
#: Connections served at once; a connection past this is closed unanswered, without reading,
#: and counted as ``over_connection_limit``.
MAX_CONNECTIONS = 64
#: Entries stored per prefix and calendar hour (UTC); past this the request is only counted.
MAX_ENTRIES_PER_HOUR = 1000
#: Total size of the data directory; past this a request is only counted.
MAX_DATA_BYTES = 64 * 1024 * 1024

#: How often the service removes what has passed its deadline. At most one minute.
SWEEP_INTERVAL_SECONDS = 30.0
#: Days of per-day counters kept.
COUNT_DAYS = 90

#: A prefix is base64url; 22 characters carry 132 bits, which is the floor.
MIN_PREFIX_CHARS = 22
MAX_PREFIX_CHARS = 128
#: A prefix with fewer different characters than this is refused: it cannot carry the randomness.
MIN_PREFIX_DISTINCT_CHARS = 10
#: The HMAC key, after base64 decoding.
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 1024
#: Longest retention a registration may ask for (90 days).
MAX_RETENTION_SECONDS = 90 * 24 * 3600
MAX_SECRET_HEADERS = 32
#: A registration may not end later than this after the moment it is made (366 days). No audit
#: runs that long, and the bound keeps ``expires_at`` plus retention far from the year 9999.
MAX_EXPIRES_AHEAD_SECONDS = 366 * 24 * 3600
#: A registration read from stdin is never larger than this.
MAX_REGISTRATION_BYTES = 64 * 1024

#: A first word of an ``Authorization`` value is kept as ``scheme`` only up to this length.
MAX_SCHEME_CHARS = 16

#: A name chosen by the sender (query parameter, path segment, label of ``Host``) is stored as it
#: came only when it is a letter, then letters and ``_ . -``, then at most ``MAX_NAME_DIGITS``
#: digits, and has at most this many characters in all; anything else is a value.
MAX_NAME_CHARS = 32
MAX_NAME_DIGITS = 3
#: A header name is stored only up to this many characters (letters, digits and ``-``).
MAX_HEADER_NAME_CHARS = 64
#: Parts stored for one path, one query or one ``Host``; what is beyond them is one HMAC together.
MAX_STORED_PARTS = 32
