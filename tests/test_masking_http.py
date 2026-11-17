"""Masking for the HTTP transport: header maps, the parsed WWW-Authenticate, query maps, and
SSE event ids as pseudonyms (docs/design/http-transport.md, 2.5, 2.6, 2.8).

Nothing calls these functions yet; they are tested on their own, like the rest of masking.
The canaries below are made up for these tests and grant nothing anywhere.
"""

import json

import pytest

from mcp_kymograph.masking import (
    HANDLE_PREFIX,
    PLACEHOLDER,
    Masker,
    parse_challenges,
)

#: Three values that must not survive in any form. Built from parts that occur nowhere else in
#: what masking writes, so that any five characters of one found in an output are a leak.
BEARER_CANARY = "zqXv" + "Jk7Wp" + "Yb3Hn" + "Lr9Td"
COOKIE_CANARY = "QmZw" + "8sKe" + "Vu4Fj" + "Rx6Gc"
SESSION_CANARY = "PoNy" + "5dGh" + "Tw2Mk" + "Ea7Us"
CANARIES = (BEARER_CANARY, COOKIE_CANARY, SESSION_CANARY)

METADATA_URL = "https://mcp.example.org/.well-known/oauth-protected-resource"

BLANKED = ("Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Mcp-Session-Id")


def masker() -> Masker:
    return Masker(handle_salt=b"\x01" * 16)


def leaked(output: object) -> list[str]:
    """Every five-character piece of a canary that appears in the output."""
    text = json.dumps(output)
    return [
        canary[start : start + 5]
        for canary in CANARIES
        for start in range(len(canary) - 4)
        if canary[start : start + 5] in text
    ]


def case_variants(name: str) -> list[str]:
    return [name, name.lower(), name.upper()]


# -- headers through the ordinary rules ----------------------------------------------------


@pytest.mark.parametrize("name", [variant for name in BLANKED for variant in case_variants(name)])
def test_the_credential_headers_are_blanked_whole_in_any_case(name):
    masked, paths = masker().mask_headers([(name, f"Bearer {BEARER_CANARY}; a=b")])
    assert masked == {name.lower(): PLACEHOLDER}
    assert paths == [name.lower()]


def test_a_bearer_token_a_cookie_and_a_session_id_appear_in_no_output_not_even_in_part():
    request = [
        ("Host", "127.0.0.1:8080"),
        ("Authorization", f"Bearer {BEARER_CANARY}"),
        ("Cookie", f"sid={COOKIE_CANARY}; theme=dark"),
        ("Mcp-Session-Id", SESSION_CANARY),
        ("Accept", "application/json, text/event-stream"),
        ("X-Forwarded-Note", f"seen Bearer {BEARER_CANARY} on the way"),
    ]
    response = [
        ("Content-Type", "text/event-stream"),
        ("Set-Cookie", f"sid={COOKIE_CANARY}; HttpOnly"),
        ("set-cookie", f"other={COOKIE_CANARY}{BEARER_CANARY}"),
        ("MCP-SESSION-ID", SESSION_CANARY),
        ("WWW-Authenticate", f'Bearer error="invalid_token", token="{BEARER_CANARY}"'),
        ("WWW-Authenticate", f"Negotiate {SESSION_CANARY}=="),
    ]
    query = f"access_token={BEARER_CANARY}&session_id={SESSION_CANARY}&cookie={COOKIE_CANARY}"
    outputs = [
        masker().mask_headers(request),
        masker().mask_headers(dict(request)),
        masker().mask_headers(response),
        masker().mask_query(query),
        masker().mask_event_id(SESSION_CANARY),
    ]
    assert leaked(outputs) == []
    # What is not a credential stays as it was.
    headers, _ = outputs[0]
    assert headers["host"] == "127.0.0.1:8080"
    assert headers["accept"] == "application/json, text/event-stream"
    assert headers["x-forwarded-note"] == f"seen Bearer {PLACEHOLDER} on the way"


def test_a_header_sent_twice_is_kept_as_a_list_whatever_its_case():
    masked, paths = masker().mask_headers(
        [("Vary", "Accept"), ("vary", "Origin"), ("Set-Cookie", "a=1"), ("SET-COOKIE", "b=2")]
    )
    assert masked == {"vary": ["Accept", "Origin"], "set-cookie": PLACEHOLDER}
    assert paths == ["set-cookie"]


def test_a_map_and_a_list_of_pairs_give_the_same_result():
    headers = {"Authorization": f"Bearer {BEARER_CANARY}", "Accept": "application/json"}
    assert masker().mask_headers(headers) == masker().mask_headers(list(headers.items()))


# -- WWW-Authenticate: the one header parsed first -----------------------------------------


@pytest.mark.parametrize("name", case_variants("WWW-Authenticate"))
def test_www_authenticate_keeps_where_a_client_is_sent_and_blanks_the_token_beside_it(name):
    challenge = (
        f'Bearer resource_metadata="{METADATA_URL}", scope="files:read files:write", '
        f'error="invalid_token", error_description="expired: Bearer {BEARER_CANARY}", '
        f'access_token="{BEARER_CANARY}"'
    )
    masked, paths = masker().mask_headers([(name, challenge)])
    assert masked == {
        "www-authenticate": [
            {
                "scheme": "Bearer",
                "params": {
                    "resource_metadata": METADATA_URL,
                    "scope": "files:read files:write",
                    "error": "invalid_token",
                    "error_description": f"expired: Bearer {PLACEHOLDER}",
                    # A parameter no specification names keeps neither name nor value.
                    masker().pseudonym("access_token"): PLACEHOLDER,
                },
            }
        ]
    }
    assert paths == [
        "www-authenticate[0].params.error_description",
        f"www-authenticate[0].params.{masker().pseudonym('access_token')}",
    ]
    assert leaked(masked) == []


def test_parameter_names_compare_without_case():
    masked, _ = masker().mask_headers(
        [("www-authenticate", f'Bearer Resource_Metadata="{METADATA_URL}", ERROR=invalid_token')]
    )
    assert masked["www-authenticate"][0]["params"] == {
        "resource_metadata": METADATA_URL,
        "error": "invalid_token",
    }


def test_several_challenges_in_one_value_and_over_several_lines():
    masked, paths = masker().mask_headers(
        [
            ("WWW-Authenticate", 'Basic realm="files", charset="UTF-8", Bearer scope="x"'),
            ("WWW-Authenticate", f"Negotiate {BEARER_CANARY}"),
        ]
    )
    assert masked["www-authenticate"] == [
        {"scheme": "Basic", "params": {"realm": "files", "charset": "UTF-8"}},
        {"scheme": "Bearer", "params": {"scope": "x"}},
        {"scheme": "Negotiate", "token68": PLACEHOLDER},
    ]
    assert paths == ["www-authenticate[2].token68"]


@pytest.mark.parametrize(
    "value",
    [
        f'Bearer realm="unterminated, token="{BEARER_CANARY}',
        f'Bearer error="a", error="{BEARER_CANARY}"',
        f'realm="{BEARER_CANARY}"',
        f"Bearer realm=a {BEARER_CANARY}",
        f"Negotiate {BEARER_CANARY}, realm=x",
        "",
        f'Bearer realm="x", ="{BEARER_CANARY}"',
    ],
)
def test_a_challenge_that_does_not_parse_is_blanked_whole(value):
    masked, paths = masker().mask_headers([("WWW-Authenticate", value)])
    assert masked == {"www-authenticate": PLACEHOLDER}
    assert paths == ["www-authenticate"]


def test_one_bad_line_blanks_every_line_of_the_header():
    masked, _ = masker().mask_headers(
        [("WWW-Authenticate", 'Bearer scope="x"'), ("WWW-Authenticate", 'Bearer "broken')]
    )
    assert masked == {"www-authenticate": PLACEHOLDER}


@pytest.mark.parametrize("name", ["X-WWW-Authenticate", "Proxy-Authenticate", "WWW-Authenticate2"])
def test_the_exception_is_anchored_on_the_name_and_closed(name):
    masked, _ = masker().mask_headers([(name, f'Bearer resource_metadata="{METADATA_URL}"')])
    assert masked == {name.lower(): PLACEHOLDER}


def test_the_parser_unescapes_quoted_values_and_keeps_token68_padding():
    assert parse_challenges(r'Digest realm="a \"b\" c", qop=auth') == [
        {"scheme": "Digest", "params": {"realm": 'a "b" c', "qop": "auth"}}
    ]
    assert parse_challenges("Negotiate YWJj==") == [{"scheme": "Negotiate", "token68": "YWJj=="}]
    assert parse_challenges("Bearer") == [{"scheme": "Bearer", "params": {}}]


# -- the query string ----------------------------------------------------------------------


def test_a_query_is_split_decoded_and_masked_like_a_map():
    masked, paths = masker().mask_query(
        f"cursor=abc&access_token={BEARER_CANARY}&api%5Fkey={COOKIE_CANARY}&x=1&x=2&flag"
        f"&note=Bearer+{SESSION_CANARY}"
    )
    assert masked == {
        "cursor": "abc",
        "access_token": PLACEHOLDER,
        "api_key": PLACEHOLDER,
        "x": ["1", "2"],
        # A field without "=" is a bare token in the query: its name is not kept either.
        masker().pseudonym("flag"): PLACEHOLDER,
        "note": f"Bearer {PLACEHOLDER}",
    }
    assert sorted(paths) == sorted(["access_token", "api_key", "note", masker().pseudonym("flag")])
    assert leaked(masked) == []


def test_an_empty_query_is_an_empty_map():
    assert masker().mask_query("") == ({}, [])


# -- SSE event ids -------------------------------------------------------------------------


def test_an_event_id_is_a_pseudonym_and_the_resumption_carries_the_same_one():
    one = masker()
    pseudonym = one.mask_event_id(SESSION_CANARY)
    assert pseudonym == one.pseudonym(SESSION_CANARY)
    assert pseudonym.startswith(HANDLE_PREFIX)
    masked, paths = one.mask_headers([("Last-Event-ID", SESSION_CANARY)])
    assert masked == {"last-event-id": pseudonym}
    assert paths == ["last-event-id"]
    # Another run, another salt: the same id is a different pseudonym.
    assert Masker(handle_salt=b"\x02" * 16).mask_event_id(SESSION_CANARY) != pseudonym


def test_distinct_event_ids_stay_distinct_and_the_empty_id_stays_empty():
    one = masker()
    assert one.mask_event_id("41") != one.mask_event_id("42")
    assert one.mask_event_id("") == ""


# -- further edge cases named for the transport ---------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["access_token", "accessToken", "ACCESS-TOKEN", "id_token", "refresh_token", "apiKey",
     "api%5Fkey", "client_secret", "password", "session_id", "Authorization", "auth"],
)  # fmt: skip
def test_a_token_in_the_query_is_blanked_whatever_the_spelling_of_its_name(name):
    masked, paths = masker().mask_query(f"{name}={BEARER_CANARY}&page=2")
    assert leaked(masked) == []
    assert masked["page"] == "2" and len(paths) == 1


@pytest.mark.parametrize(
    "value",
    [f"Bearer%20{BEARER_CANARY}", f"Bearer+{BEARER_CANARY}",
     "eyJhbGci" + "OiJub25lIn0" + ".eyJzdWIiOiJ4In0.c2ln"],  # a JWT's shape, signed by nobody
)  # fmt: skip
def test_a_credential_shaped_value_under_a_harmless_name_is_masked_by_its_shape(value):
    masked, paths = masker().mask_query(f"note={value}")
    assert leaked(masked) == []
    assert "eyJhbGci" not in json.dumps(masked)
    assert paths == ["note"]


def test_a_query_name_given_twice_with_a_token_is_blanked_as_a_whole():
    masked, _ = masker().mask_query(f"token=a&token={BEARER_CANARY}&Token=b")
    assert masked == {"token": PLACEHOLDER, "Token": PLACEHOLDER}


def test_several_cookies_over_several_lines_in_mixed_case_are_blanked_whole():
    masked, paths = masker().mask_headers(
        [
            ("Cookie", f"a=1; sid={COOKIE_CANARY}"),
            ("COOKIE", f"other={SESSION_CANARY}"),
            ("set-COOKIE", f"sid={COOKIE_CANARY}; Path=/; HttpOnly"),
            ("Authorization", f"Basic {BEARER_CANARY}"),
            ("authorization", f"Bearer {SESSION_CANARY}"),
        ]
    )
    assert masked == {
        "cookie": PLACEHOLDER,
        "set-cookie": PLACEHOLDER,
        "authorization": PLACEHOLDER,
    }
    assert sorted(paths) == ["authorization", "cookie", "set-cookie"]
    assert leaked(masked) == []


def test_www_authenticate_with_several_schemes_keeps_each_scheme_apart():
    masked, _ = masker().mask_headers(
        [
            (
                "WWW-Authenticate",
                f'Basic realm="api", Bearer resource_metadata="{METADATA_URL}", '
                f'error="insufficient_scope", scope="tools:call", DPoP algs="ES256", '
                f"Negotiate {BEARER_CANARY}",
            )
        ]
    )
    schemes = [challenge["scheme"] for challenge in masked["www-authenticate"]]
    assert schemes == ["Basic", "Bearer", "DPoP", "Negotiate"]
    bearer = masked["www-authenticate"][1]["params"]
    assert bearer == {
        "resource_metadata": METADATA_URL,
        "error": "insufficient_scope",
        "scope": "tools:call",
    }
    assert masked["www-authenticate"][3] == {"scheme": "Negotiate", "token68": PLACEHOLDER}
    assert leaked(masked) == []


def test_existing_masking_is_unchanged_by_the_http_functions():
    # The HTTP functions are additions: mask_json and mask_text say what they said before.
    one = masker()
    assert one.mask_json({"Authorization": "x", "name": "n"}) == (
        {"Authorization": PLACEHOLDER, "name": "n"},
        ["Authorization"],
    )
    assert one.mask_text("WWW-Authenticate: Bearer abcdefghijkl")[1] == 1


# -- edge cases of schemes, parameters and credential headers -------------------------------


@pytest.mark.parametrize(
    "value",
    [f"Bearer, {BEARER_CANARY}", BEARER_CANARY, f'Bearer error="invalid_token", {BEARER_CANARY}',
     f"Bearer, {BEARER_CANARY} realm=x"],
)  # fmt: skip
def test_a_word_in_a_schemes_place_that_is_no_known_scheme_is_blanked(value):
    masked, paths = masker().mask_headers([("WWW-Authenticate", value)])
    assert leaked(masked) == []
    assert any(path.endswith(".scheme") for path in paths) or masked == {
        "www-authenticate": PLACEHOLDER
    }


@pytest.mark.parametrize(
    "value",
    [f"Bearer abc%2B{BEARER_CANARY}", f"Bearer {BEARER_CANARY} x", "a a a",
     'Bearer realm="abc\\\\', "Bearer realm=, scope=x", "Negotiate abc def"],
)  # fmt: skip
def test_a_word_where_only_a_parameter_or_token68_may_stand_blanks_the_header(value):
    masked, paths = masker().mask_headers([("WWW-Authenticate", value)])
    assert masked == {"www-authenticate": PLACEHOLDER}
    assert paths == ["www-authenticate"]


def test_known_schemes_keep_their_name_in_any_case_and_spacing_is_free():
    masked, _ = masker().mask_headers(
        [("www-authenticate", 'bearer realm = "x" ,\tscope=y, DIGEST realm="z", qop="auth"')]
    )
    assert masked["www-authenticate"] == [
        {"scheme": "bearer", "params": {"realm": "x", "scope": "y"}},
        {"scheme": "DIGEST", "params": {"realm": "z", "qop": "auth"}},
    ]


@pytest.mark.parametrize(
    "value", [f"Bearer {BEARER_CANARY}=x", f'Bearer token_{BEARER_CANARY}="v"', 'Digest nonce="n"']
)
def test_a_parameter_no_specification_names_keeps_neither_name_nor_value(value):
    masked, paths = masker().mask_headers([("WWW-Authenticate", value)])
    (challenge,) = masked["www-authenticate"]
    assert list(challenge["params"].values()) == [PLACEHOLDER]
    assert next(iter(challenge["params"])).startswith(HANDLE_PREFIX)
    assert leaked(masked) == [] and len(paths) == 1


@pytest.mark.parametrize(
    "query",
    [BEARER_CANARY, f"token_{BEARER_CANARY}=1", f"{BEARER_CANARY}%3D",
     f"a=1;access_token={BEARER_CANARY}", f"api%255Fkey={BEARER_CANARY}",
     f"x={'Bearer%2520'}{BEARER_CANARY}"],
)  # fmt: skip
def test_a_credential_as_a_query_name_or_behind_a_semicolon_does_not_survive(query):
    masked, paths = masker().mask_query(query)
    assert leaked(masked) == [] and paths


def test_a_credential_in_a_url_inside_a_value_is_blanked():
    one = masker()
    headers, paths = one.mask_headers(
        [
            ("Location", f"https://example.org/cb?state=1&access_token={BEARER_CANARY}"),
            ("WWW-Authenticate", f'Bearer resource_metadata="https://x/m?api_key={BEARER_CANARY}"'),
        ]
    )
    assert headers["location"] == f"https://example.org/cb?state=1&access_token={PLACEHOLDER}"
    assert headers["www-authenticate"][0]["params"]["resource_metadata"] == (
        f"https://x/m?api_key={PLACEHOLDER}"
    )
    assert paths == ["location", "www-authenticate[0].params.resource_metadata"]
    query, _ = one.mask_query(f"redirect=https%3A%2F%2Fx%2F%3Faccess_token%3D{BEARER_CANARY}")
    assert query == {"redirect": f"https://x/?access_token={PLACEHOLDER}"}


def test_the_credential_headers_and_a_broken_challenge_are_blanked_without_any_needle(monkeypatch):
    from mcp_kymograph import masking

    monkeypatch.setattr(masking, "DEFAULT_KEY_NEEDLES", frozenset())
    bare = masking.Masker(handle_salt=b"\x01" * 16)
    assert not bare.needles
    headers = [(name, f"x {BEARER_CANARY}") for name in BLANKED]
    headers.append(("WWW-Authenticate", f'Bearer realm="x", ="{BEARER_CANARY}"'))
    masked, _ = bare.mask_headers(headers)
    assert set(masked.values()) == {PLACEHOLDER}
    assert len(masked) == len(BLANKED) + 1


def test_too_many_challenges_or_query_fields_are_blanked_whole():
    from mcp_kymograph.masking import MAX_CHALLENGES, MAX_QUERY_FIELDS

    many = ", ".join(["Basic"] * (MAX_CHALLENGES + 1))
    assert masker().mask_headers([("WWW-Authenticate", many)])[0] == {
        "www-authenticate": PLACEHOLDER
    }
    fits = ", ".join(["Basic"] * MAX_CHALLENGES)
    assert len(masker().mask_headers([("WWW-Authenticate", fits)])[0]["www-authenticate"]) == 64
    query = "&".join(f"p{n}=1" for n in range(MAX_QUERY_FIELDS + 1))
    assert masker().mask_query(query) == ({PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER])
    assert len(masker().mask_query(query.rsplit("&", 1)[0])[0]) == MAX_QUERY_FIELDS


def test_a_resumption_sent_twice_carries_each_pseudonym():
    one = masker()
    masked, _ = one.mask_headers([("Last-Event-ID", "7"), ("last-event-id", "8")])
    assert masked == {"last-event-id": [one.mask_event_id("7"), one.mask_event_id("8")]}


def test_too_many_challenges_over_several_lines_are_blanked_whole():
    line = ", ".join(["Basic"] * 40)
    masked, _ = masker().mask_headers([("WWW-Authenticate", line), ("WWW-Authenticate", line)])
    assert masked == {"www-authenticate": PLACEHOLDER}


def test_a_semicolon_separates_query_fields():
    assert masker().mask_query("a=1;b=2&c=3") == ({"a": "1", "b": "2", "c": "3"}, [])


@pytest.mark.parametrize("name", ["a+b", "x" * 33, "na%C3%AFve", "a/b"])
def test_a_query_name_that_does_not_read_like_one_is_not_kept(name):
    masked, paths = masker().mask_query(f"{name}=1")
    (key,) = masked
    assert key.startswith(HANDLE_PREFIX) and masked[key] == PLACEHOLDER and paths == [key]


def test_a_scheme_glued_to_what_follows_blanks_the_header():
    masked, _ = masker().mask_headers([("WWW-Authenticate", "Bearer/abc")])
    assert masked == {"www-authenticate": PLACEHOLDER}


# -- decoding stages, fragments, names, fail closed -----------------------------------------

#: A token with every character a token may carry besides letters and digits.
SYMBOL_CANARY = "Hb8" + "Wq+Nc4" + "/Td-Ky" + "6._Xs~" + "Fv2="


def symbol_leaked(output: object) -> list[str]:
    text = json.dumps(output)
    pieces = [SYMBOL_CANARY[start : start + 5] for start in range(len(SYMBOL_CANARY) - 4)]
    return leaked(output) + [piece for piece in pieces if piece in text]


def quoted(text: str, times: int) -> str:
    from urllib.parse import quote

    for _ in range(times):
        text = quote(text, safe="")
    return text


@pytest.mark.parametrize("times", [1, 2, 3])
def test_a_token_with_a_plus_does_not_fall_apart_when_decoded_again(times):
    one = masker()
    for query in (
        f"note={quoted('Bearer ' + SYMBOL_CANARY, times)}",
        f"next={quoted('https://x/cb?access_token=' + SYMBOL_CANARY, times)}",
        f"next=https://x/cb?access_token={quoted(SYMBOL_CANARY, times)}",
    ):
        masked, paths = one.mask_query(query)
        assert symbol_leaked(masked) == [], query
        assert paths, query


def test_a_plus_is_a_space_only_in_the_first_decoding_of_a_query():
    assert masker().mask_query("q=a+b&r=a%2Bb&s=a%252Bb") == (
        {"q": "a b", "r": "a+b", "s": "a+b"},
        [],
    )


def test_a_credential_in_an_earlier_decoding_blanks_the_value_whole():
    # Decoded once, the value holds a URL with a token; decoded again, the token's "%2B"
    # would be a "+". Whatever the last form shows, the value is not kept.
    masked, paths = masker().mask_query(
        f"next={quoted('https://x/cb?access_token=ab' + quoted('+', 1) + BEARER_CANARY, 1)}"
    )
    assert masked == {"next": PLACEHOLDER} and paths == ["next"]


def test_three_decodings_are_read_and_a_value_still_encoded_after_them_is_blanked():
    from mcp_kymograph.masking import MAX_DECODINGS

    assert MAX_DECODINGS == 3
    name = quoted("api_key", 3)
    masked, _ = masker().mask_query(f"{name}={BEARER_CANARY}")
    assert masked == {"api_key": PLACEHOLDER}
    masked, _ = masker().mask_query(f"x={quoted('Bearer ' + BEARER_CANARY, 3)}")
    assert masked == {"x": f"Bearer {PLACEHOLDER}"}
    # Four times encoded, the last form still decodes: not read to the end, so not kept.
    masked, _ = masker().mask_query(f"x={quoted('Bearer ' + BEARER_CANARY, 4)}")
    assert masked == {"x": PLACEHOLDER}
    masked, _ = masker().mask_headers([("X-Note", quoted("Bearer " + BEARER_CANARY, 4))])
    assert masked == {"x-note": PLACEHOLDER}
    # Text that merely holds a percent sign is not blanked for it.
    assert masker().mask_query("x=100%25")[0] == {"x": "100%"}


@pytest.mark.parametrize(
    "url",
    [f"https://x/cb#access_token={BEARER_CANARY}&token_type=bearer",
     f"https://x/cb?state=1#access_token={BEARER_CANARY}",
     f"https://x/cb?a=1;access_token={BEARER_CANARY}",
     f"https://x/cb?api%5Fkey={BEARER_CANARY}",
     f"https://idp/a?redirect_uri={quoted('https://app/cb?access_token=' + BEARER_CANARY, 1)}",
     f"https://idp/a?next=https://app/cb?access_token={BEARER_CANARY}&x=1",
     f"https://x/?{'a' * 70}_access_token={BEARER_CANARY}",
     f"https://x/?{BEARER_CANARY}=1",
     f"https://x/cb?code={BEARER_CANARY}"],
)  # fmt: skip
def test_a_credential_in_a_url_in_a_header_or_a_parameter_does_not_survive(url):
    one = masker()
    masked, paths = one.mask_headers([("Location", url)])
    assert leaked(masked) == [] and paths == ["location"]
    masked, paths = one.mask_headers([("WWW-Authenticate", f'Bearer resource_metadata="{url}"')])
    assert leaked(masked) == []
    assert paths == ["www-authenticate[0].params.resource_metadata"]


def test_what_is_blanked_in_a_url_keeps_the_rest_of_it():
    one = masker()
    masked, _ = one.mask_headers(
        [("Location", f"https://x/cb#access_token={BEARER_CANARY}&state=abc")]
    )
    assert masked == {"location": f"https://x/cb#access_token={PLACEHOLDER}&state=abc"}
    masked, _ = one.mask_headers([("Location", f"https://x/?{'a' * 70}={BEARER_CANARY}&b=1")])
    assert masked == {"location": f"https://x/?{PLACEHOLDER}={PLACEHOLDER}&b=1"}


def test_a_name_in_a_url_is_kept_up_to_its_bound():
    from mcp_kymograph.masking import MAX_NAME_LENGTH

    fits = "a_" * (MAX_NAME_LENGTH // 2)
    masked, paths = masker().mask_headers([("Location", f"https://x/?{fits}=1")])
    assert masked == {"location": f"https://x/?{fits}=1"} and paths == []
    masked, _ = masker().mask_headers([("Location", f"https://x/?{fits}b=1")])
    assert masked == {"location": f"https://x/?{PLACEHOLDER}={PLACEHOLDER}"}


@pytest.mark.parametrize(
    "value",
    [f"access_token={BEARER_CANARY}", f"x, access_token={BEARER_CANARY}",
     f'("access_token={BEARER_CANARY}")', f"a <access_token={BEARER_CANARY}>"],
)  # fmt: skip
def test_a_name_value_pair_standing_on_its_own_in_a_header_is_masked(value):
    masked, paths = masker().mask_headers([("X-Query", value)])
    assert leaked(masked) == [] and paths == ["x-query"]


def test_ordinary_name_value_pairs_in_headers_are_kept():
    headers = [
        ("Content-Type", "multipart/form-data; boundary=----Boundary7MA4YWxk"),
        ("Accept", "text/html;q=0.9, */*;q=0.8"),
        ("Cache-Control", "max-age=0"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Link", '<https://x/next>; rel="next"'),
    ]
    masked, paths = masker().mask_headers(headers)
    assert masked == {name.lower(): value for name, value in headers} and paths == []


def test_a_query_value_holding_a_pair_is_masked():
    masked, paths = masker().mask_query(f"x={quoted('access_token=' + BEARER_CANARY, 1)}")
    assert masked == {"x": f"access_token={PLACEHOLDER}"} and paths == ["x"]


def test_a_fragment_passed_with_a_query_is_masked_under_its_own_key():
    one = masker()
    masked, paths = one.mask_query(f"a=1#access_token={BEARER_CANARY}&state=x")
    assert masked == {"a": "1", "#": {"access_token": PLACEHOLDER, "state": "x"}}
    assert paths == ["#.access_token"]
    assert one.mask_query("a=1#") == ({"a": "1", "#": {}}, [])
    # A name that decodes to "#" cannot take the fragment's key.
    masked, _ = one.mask_query("%23=1")
    assert "#" not in masked


@pytest.mark.parametrize(
    "name",
    [BEARER_CANARY, "0123456789abcdef0123456789abcdef", "0123456789abcdef",
     "AKIA" + "ABCDEFGHIJKLMNOP", "a" * 25, "a12345", "aBcDeFgHiJ",
     # Plain, but a needle with something after it: what follows may be the credential.
     "token_abcdef", "apikey_x", "my_secret_value"],
)  # fmt: skip
def test_a_query_name_shaped_like_a_value_is_not_kept(name):
    masked, paths = masker().mask_query(f"{name}=1")
    (key,) = masked
    assert key.startswith(HANDLE_PREFIX) and masked[key] == PLACEHOLDER and paths == [key]


@pytest.mark.parametrize(
    "name",
    ["includeDeletedItems", "utm_source", "filter[0][name]", "page2SizeLimit", "X-B3-TraceId",
     "a" * 24, "a1234", "aBcDe", "page2Size"],
)  # fmt: skip
def test_a_query_name_that_reads_like_one_is_kept(name):
    assert masker().mask_query(f"{name}=1") == ({name: "1"}, [])


@pytest.mark.parametrize(
    "name", ["code", "sig", "signature", "key", "X-Amz-Signature", "X-Amz-Credential", "otp"]
)
def test_a_credential_name_without_a_needle_is_blanked_too(name):
    masked, paths = masker().mask_query(f"{name}={BEARER_CANARY}&page=2")
    assert masked == {name: PLACEHOLDER, "page": "2"} and paths == [name]


def test_query_and_url_credentials_are_blanked_without_any_needle(monkeypatch):
    from mcp_kymograph import masking

    monkeypatch.setattr(masking, "DEFAULT_KEY_NEEDLES", frozenset())
    bare = masking.Masker(handle_salt=b"\x01" * 16)
    assert not bare.needles
    masked, _ = bare.mask_query(f"access_token={BEARER_CANARY}&token_x=1&api_key={COOKIE_CANARY}")
    assert leaked(masked) == []
    assert masked["access_token"] == PLACEHOLDER and masked["api_key"] == PLACEHOLDER
    masked, _ = bare.mask_headers([("Location", f"https://x/?access_token={BEARER_CANARY}")])
    assert leaked(masked) == []
    masked, _ = bare.mask_headers([("Authorization ", BEARER_CANARY)])
    assert masked == {"authorization": PLACEHOLDER}


@pytest.mark.parametrize(
    "name",
    [f"X-Auth-{BEARER_CANARY}", BEARER_CANARY, "X-" + "a" * 63, "X Spaced",
     "X-" + "Ab-" * 20 + "Abc", "AKIA" + "ABCDEFGHIJKLMNOP"],
)  # fmt: skip
def test_a_header_name_that_does_not_read_like_one_is_not_kept(name):
    one = masker()
    masked, paths = one.mask_headers([(name, "1"), ("Accept", "*/*")])
    hidden = one.pseudonym(name.strip().lower())
    assert masked == {hidden: PLACEHOLDER, "accept": "*/*"} and paths == [hidden]
    assert leaked(masked) == []


def test_a_header_name_is_kept_up_to_its_bound_and_stripped():
    fits = "X-" + "Ab-" * 20 + "Ab"
    assert len(fits) == 64
    masked, _ = masker().mask_headers([(fits, "1"), (" Accept\t", "*/*")])
    assert masked == {fits.lower(): "1", "accept": "*/*"}


@pytest.mark.parametrize(
    "headers",
    [[(b"authorization", "x")], [("Accept", None)], [("Accept", b"x")], [("a", "b", "c")],
     ["TE"], "TE"],
)  # fmt: skip
def test_anything_but_pairs_of_strings_blanks_the_whole_map(headers):
    assert masker().mask_headers(headers) == ({PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER])


def test_a_path_is_recorded_for_a_credential_in_a_decoded_url():
    _, paths = masker().mask_query(f"redirect={quoted('https://x/?access_token=' + 'abc', 1)}")
    assert paths == ["redirect"]


def test_the_bound_on_challenges_holds_over_several_lines():
    from mcp_kymograph.masking import MAX_CHALLENGES

    half = ", ".join(["Basic"] * (MAX_CHALLENGES // 2))
    fits, _ = masker().mask_headers([("WWW-Authenticate", half), ("WWW-Authenticate", half)])
    assert len(fits["www-authenticate"]) == MAX_CHALLENGES
    over, _ = masker().mask_headers(
        [("WWW-Authenticate", half), ("WWW-Authenticate", half + ", Basic")]
    )
    assert over == {"www-authenticate": PLACEHOLDER}


def test_a_parameter_twice_in_any_case_blanks_the_header():
    masked, _ = masker().mask_headers([("WWW-Authenticate", 'Bearer realm="a", REALM="b"')])
    assert masked == {"www-authenticate": PLACEHOLDER}


def test_the_query_bound_is_counted_before_the_fields_are_kept():
    from mcp_kymograph.masking import MAX_QUERY_FIELDS

    # Empty fields between separators are not fields.
    fits = "&&".join(f"p{n}=1" for n in range(MAX_QUERY_FIELDS))
    assert len(masker().mask_query(fits)[0]) == MAX_QUERY_FIELDS
    assert masker().mask_query(fits + "&x=1")[0] == {PLACEHOLDER: PLACEHOLDER}


def test_hostile_values_are_masked_in_linear_time():
    import time

    one = masker()
    for unit in ("#a=1", "?a", ",", "a=", "%25", "&a=b", " a"):
        small = unit * 20_000
        large = unit * 80_000
        started = time.perf_counter()
        one.mask_headers([("Location", small)])
        one.mask_query(small)
        middle = time.perf_counter()
        one.mask_headers([("Location", large)])
        one.mask_query(large)
        ended = time.perf_counter()
        # Four times the input; quadratic would be sixteen times the time.
        assert ended - middle < 10 * max(middle - started, 0.01), unit


def test_a_header_keeps_its_value_as_written_and_checks_the_decoded_one_too():
    one = masker()
    masked, paths = one.mask_headers([("Location", "https://x/a%20b?x=1")])
    assert masked == {"location": "https://x/a%20b?x=1"} and paths == []
    # Decoded, the value is a bearer token; as written, no rule sees one.
    masked, paths = one.mask_headers([("X-Note", f"Bearer%20{BEARER_CANARY}")])
    assert masked == {"x-note": PLACEHOLDER} and paths == ["x-note"]
    # Decoded, a name holds a needle: the header is blanked whole, not only as written.
    masked, paths = one.mask_headers([("Location", f"https://x/?api%5Fkey={BEARER_CANARY}")])
    assert masked == {"location": PLACEHOLDER} and paths == ["location"]


def test_a_name_in_a_url_outside_the_plain_characters_is_not_kept():
    masked, _ = masker().mask_headers([("Location", "https://x/?$filter=1&c=2")])
    assert masked == {"location": f"https://x/?{PLACEHOLDER}={PLACEHOLDER}&c=2"}


def test_a_name_in_a_url_is_read_decoded():
    masked, paths = masker().mask_headers([("Location", "https://x/?q%5B%5D=1&a%5Fb=2")])
    assert masked == {"location": "https://x/?q%5B%5D=1&a%5Fb=2"} and paths == []


# -- pairs inside values, "+" in later forms, names -----------------------------------------


@pytest.mark.parametrize(
    "value",
    [f"a=1,access_token={BEARER_CANARY}", f"a=1|access_token={BEARER_CANARY}",
     f"note=access_token={BEARER_CANARY}", f"x,access_token={BEARER_CANARY}",
     f"'access_token={BEARER_CANARY}", f"(access_token={BEARER_CANARY}",
     f"https://x/cb?state=1,access_token={BEARER_CANARY}",
     f"https://x/cb/access_token={BEARER_CANARY}", f"urn:x:access_token={BEARER_CANARY}"],
)  # fmt: skip
def test_a_pair_inside_another_pairs_value_is_read_too(value):
    one = masker()
    masked, paths = one.mask_headers([("X-Debug", value)])
    assert leaked(masked) == [] and paths == ["x-debug"]
    masked, _ = one.mask_headers([("WWW-Authenticate", f'Bearer error_description="{value}"')])
    assert leaked(masked) == []
    masked, _ = one.mask_query(f"x={quoted(value, 1)}")
    assert leaked(masked) == []


def test_a_blanked_value_runs_past_a_question_mark_a_comma_and_a_space():
    for after in ("?", ",", "|", " ", "\t", ">", "\n", "\u00a0"):
        masked, _ = masker().mask_headers(
            [("Location", f"https://x/cb?access_token=ab{after}{BEARER_CANARY}&state=1")]
        )
        assert masked == {"location": f"https://x/cb?access_token={PLACEHOLDER}&state=1"}


def test_a_plus_is_read_as_a_space_wherever_it_could_be():
    one = masker()
    assert one.mask_headers([("X-Note", f"Bearer+{BEARER_CANARY}")])[0] == {"x-note": PLACEHOLDER}
    assert one.mask_query(f"x=Bearer%2B{BEARER_CANARY}")[0] == {"x": PLACEHOLDER}
    nested = quoted(f"https://app/cb?note=Bearer{quoted('+', 1)}{BEARER_CANARY}", 1)
    assert one.mask_query(f"next={nested}")[0] == {"next": PLACEHOLDER}
    # A plus that hides nothing stays.
    assert one.mask_headers([("X-Note", "a+b")])[0] == {"x-note": "a+b"}


def test_a_name_in_a_url_follows_the_rules_of_a_query_name():
    one = masker()
    for name in ("token_abcdef", f"token_{BEARER_CANARY.lower()}", "AKIA" + "ABCDEFGHIJKLMNOP",
                 "aB-cD-eF-gH-iJ", "a1b2c3d"):  # fmt: skip
        masked, _ = one.mask_headers([("Location", f"https://x/?{name}=1&b=2")])
        assert masked == {"location": f"https://x/?{PLACEHOLDER}={PLACEHOLDER}&b=2"}, name
    for name in ("pwd", "X-Goog-Signature", "X-Goog-Credential", "X-Amz-Security-Token"):
        masked, _ = one.mask_headers([("Location", f"https://x/?{name}={BEARER_CANARY}")])
        assert masked == {"location": f"https://x/?{name}={PLACEHOLDER}"}, name


def test_extended_parameters_and_paths_stay_readable():
    headers = [
        ("Link", "<https://x/n>; rel=\"next\"; title*=UTF-8'de'n%c3%a4chstes"),
        ("Content-Disposition", "attachment; filename*=UTF-8''r%C3%A9port.pdf"),
        ("Location", "https://example.com/files/aGVsbG8="),
        ("Location2", "https://maps.example.org/@52.5,13.4,12z/data=!3m1"),
        ("Server-Timing", 'cache;desc="Cache Read";dur=23.2'),
        ("Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43"),
    ]
    masked, paths = masker().mask_headers(headers)
    assert masked == {name.lower(): value for name, value in headers} and paths == []


@pytest.mark.parametrize("value", [None, 123, b"a=1", ["a=1"], "TE"])
def test_anything_but_the_expected_type_is_blanked_whole(value):
    blanked = ({PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER])
    if not isinstance(value, str):
        assert masker().mask_query(value) == blanked
    assert masker().mask_headers(value) == blanked


def test_a_list_pair_is_a_pair_and_paths_are_named_once():
    one = masker()
    masked, paths = one.mask_headers(
        [["Accept", "*/*"], ("Location", "https://x/?code=a&code=b"), ("location", "/?code=c")]
    )
    assert masked == {
        "accept": "*/*",
        "location": [f"https://x/?code={PLACEHOLDER}&code={PLACEHOLDER}", f"/?code={PLACEHOLDER}"],
    }
    assert paths == ["location"]
    _, paths = one.mask_query(f"code=a&code=b&access_token={BEARER_CANARY}")
    assert len(paths) == len(set(paths))


def test_pairs_inside_values_are_read_in_linear_time():
    import time

    one = masker()
    for unit in ("a=1,", "=a", "note=", "a=b=", "/a=", "access_token=x,"):
        small, large = unit * 20_000, unit * 80_000
        started = time.perf_counter()
        one.mask_headers([("Location", small)])
        middle = time.perf_counter()
        one.mask_headers([("Location", large)])
        ended = time.perf_counter()
        assert ended - middle < 10 * max(middle - started, 0.01), unit


# -- every separator, quoted values, rules in order -----------------------------------------


@pytest.mark.parametrize("before", list("?&;#=,|/:\"'(<> \t"))
def test_a_pair_is_read_after_every_separator(before):
    masked, paths = masker().mask_headers([("X-Debug", f"x{before}access_token={BEARER_CANARY}")])
    # The name is read as the name, not swallowed into a longer one that is blanked whole.
    assert masked == {"x-debug": f"x{before}access_token={PLACEHOLDER}"} and paths == ["x-debug"]


def test_markup_and_arrows_hide_no_pair():
    one = masker()
    for value in (f"<b>access_token={BEARER_CANARY}</b>", f"user->password={BEARER_CANARY}"):
        masked, _ = one.mask_headers([("X-Debug", value)])
        assert leaked(masked) == [], value
    masked, _ = one.mask_query(f"x={quoted('>token=' + BEARER_CANARY, 1)}")
    assert leaked(masked) == []


@pytest.mark.parametrize(
    ("value", "kept"),
    [(f'access_token="{BEARER_CANARY} x" next', ""),
     (f"token='{BEARER_CANARY};x' ;next", ";next"),
     (f'token="{BEARER_CANARY};x";next', ";next"),
     (f"token=<{BEARER_CANARY};x>;next", ";next"),
     (f"password=  {BEARER_CANARY} next;rest", ";rest"),
     (f"password=\n{BEARER_CANARY}", ""),
     (f'token="ab\\"{BEARER_CANARY}";next', ""),
     (f'msg="token=\\"ab;{BEARER_CANARY}\\""', ""),
     (f'token="ab\\";{BEARER_CANARY}";next', ";next"),
     (f"msg=token=\\'ab;{BEARER_CANARY}\\';next", ";next"),
     (f"msg=token=\\<ab#{BEARER_CANARY}>&next", "&next"),
     (f'msg=token=\\"{BEARER_CANARY}\\";next', ";next"),
     (f"access_token=Bearer <{BEARER_CANARY}>;x", ";x"),
     (f'access_token=Bearer "{BEARER_CANARY}";x', ";x"),
     (f'token="{BEARER_CANARY}', "")],
)  # fmt: skip
def test_a_blanked_value_runs_to_a_separator_outside_quotes(value, kept):
    masked, _ = masker().mask_headers([("X-Debug", value)])
    assert leaked(masked) == []
    assert masked["x-debug"].endswith(f"={PLACEHOLDER}{kept}")


@pytest.mark.parametrize("end", list(";#&"))
def test_a_blanked_value_ends_at_a_separator_and_the_rest_stays(end):
    masked, _ = masker().mask_headers([("X-Debug", f"access_token=ab{end}rest")])
    assert masked == {"x-debug": f"access_token={PLACEHOLDER}{end}rest"}


def test_lone_surrogates_keep_distinct_pseudonyms():
    one = masker()
    assert len({one.pseudonym("\ud800"), one.pseudonym("\udfff"), one.pseudonym("?")}) == 3


def test_the_text_rules_come_before_the_pairs():
    one = masker()
    masked, _ = one.mask_headers([("X-Debug", f"access_token=Bearer {BEARER_CANARY}")])
    assert leaked(masked) == []
    masked, _ = one.mask_query(f"x={quoted('access_token=Bearer ' + BEARER_CANARY, 1)}")
    assert leaked(masked) == []
    masked, paths = one.mask_headers([("X-Debug", f"note Bearer {BEARER_CANARY}")])
    assert masked == {"x-debug": f"note Bearer {PLACEHOLDER}"} and paths == ["x-debug"]


def test_a_star_is_kept_only_at_the_end_of_a_name():
    masked, _ = masker().mask_headers([("Link", "<x>; a*b=1; title*=x")])
    assert masked == {"link": f"<x>; {PLACEHOLDER}={PLACEHOLDER}; title*=x"}


def test_an_empty_string_for_headers_is_blanked_whole():
    assert masker().mask_headers("") == ({PLACEHOLDER: PLACEHOLDER}, [PLACEHOLDER])


def test_a_lone_surrogate_in_a_name_or_an_id_does_not_raise():
    one = masker()
    masked, _ = one.mask_headers([("X-\ud800", "1"), ("Last-Event-ID", "\ud800")])
    assert set(masked.values()) == {PLACEHOLDER, one.mask_event_id("\ud800")}
    masked, _ = one.mask_query("\ud800=1")
    assert list(masked.values()) == [PLACEHOLDER]
