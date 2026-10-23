import pytest

from tailisman import MAX_BODY, MAX_TOKEN, ErrorCode, InMemoryReplayStore, TailismanError, Verifier, extract_token
from tailisman._token import Claim, derive_consumer_key, encode, format_key, new_nonce

MASTER = b"\x07" * 32
AUD = "https://heckle.example.com"
KEY = derive_consumer_key(MASTER, AUD)
NOW = 1_800_000_000


def token(**overrides) -> str:
    fields = dict(node_id="nEXAMPLE1CNTRL", node_name="laptop", login="owner@example.com", audience=AUD, issued_at=NOW, expires_at=NOW + 60, nonce=new_nonce())
    return encode(Claim(**{**fields, **overrides}), KEY)


def verifier(now=NOW, **kwargs) -> Verifier:
    return Verifier(key=format_key(KEY), audience=AUD, clock=lambda: now, **kwargs)


def code_of(v: Verifier, t: str) -> str:
    with pytest.raises(TailismanError) as caught:
        v.verify(t)
    return caught.value.code


def test_valid_token_yields_claim():
    claim = verifier().verify(token())
    assert (claim.node_id, claim.node_name, claim.login, claim.audience) == ("nEXAMPLE1CNTRL", "laptop", "owner@example.com", AUD)


def test_audience_is_normalised_on_construction():
    v = Verifier(key=format_key(KEY), audience="HTTPS://heckle.example.com:443/", clock=lambda: NOW)
    assert v.verify(token()).audience == AUD


def test_bad_signature():
    t = token()
    assert code_of(verifier(), encode(Claim("n", "laptop", "owner@example.com", AUD, NOW, NOW + 60, new_nonce()), b"\x00" * 32)) == ErrorCode.BAD_SIGNATURE
    assert code_of(verifier(), t[:-1] + ("A" if t[-1] != "A" else "B")) in (ErrorCode.BAD_SIGNATURE, ErrorCode.MALFORMED)


def test_wrong_audience():
    assert code_of(verifier(), token(audience="https://notes.example.com")) == ErrorCode.WRONG_AUDIENCE


def test_expired_after_leeway():
    t = token(expires_at=NOW + 60)
    assert verifier(now=NOW + 65).verify(t)
    assert code_of(verifier(now=NOW + 66), token(expires_at=NOW + 60)) == ErrorCode.EXPIRED


def test_not_yet_valid():
    assert code_of(verifier(now=NOW - 6), token()) == ErrorCode.NOT_YET_VALID


def test_second_use_is_replayed():
    v, t = verifier(), token()
    v.verify(t)
    assert code_of(v, t) == ErrorCode.REPLAYED


def test_shared_store_refuses_replay_across_verifiers():
    store, t = InMemoryReplayStore(), token()
    verifier(replay=store).verify(t)
    assert code_of(verifier(replay=store), t) == ErrorCode.REPLAYED


def test_replay_store_forgets_after_until():
    store = InMemoryReplayStore()
    assert store.claim("n1", until=10, now=0)
    assert not store.claim("n1", until=10, now=10)
    assert store.claim("n1", until=30, now=11)


def test_device_recheck():
    assert verifier(devices=["laptop"]).verify(token())
    assert verifier(devices=["nEXAMPLE1CNTRL"]).verify(token())
    assert code_of(verifier(devices=["phone"]), token()) == ErrorCode.DEVICE_NOT_ALLOWED


def test_malformed():
    assert code_of(verifier(), "not a token") == ErrorCode.MALFORMED
    assert code_of(verifier(), format_key(KEY)) == ErrorCode.MALFORMED


def test_token_passed_as_key_fails_at_construction():
    with pytest.raises(TailismanError) as caught:
        Verifier(key=token(), audience=AUD)
    assert caught.value.code == ErrorCode.MALFORMED


def test_extract_token_from_both_bodies():
    assert extract_token("application/json", b'{"token": "tsm1.a.b"}') == "tsm1.a.b"
    assert extract_token("application/json; charset=utf-8", b'{"token": "tsm1.a.b"}') == "tsm1.a.b"
    assert extract_token("application/x-www-form-urlencoded", b"token=tsm1.a.b") == "tsm1.a.b"


@pytest.mark.parametrize("content_type,body", [
    ("text/plain", b"tsm1.a.b"),
    (None, b'{"token": "x"}'),
    ("application/json", b"[1]"),
    ("application/json", b'{"token": 1}'),
    ("application/json", b"\xff"),
    ("application/x-www-form-urlencoded", b"token=a&token=b"),
    ("application/x-www-form-urlencoded", b"other=1"),
])
def test_extract_token_refuses_other_bodies(content_type, body):
    with pytest.raises(TailismanError) as caught:
        extract_token(content_type, body)
    assert caught.value.code == ErrorCode.MALFORMED


@pytest.mark.parametrize("content_type,body", [
    ("application/json", b"[" * 100_000 + b"]" * 100_000),
    ("application/json", b'{"token": {"token": ' * 5_000 + b"1" + b"}" * 5_000),
    ("application/json", b'{"token": "' + b"a" * (MAX_TOKEN + 1) + b'"}'),
    ("application/x-www-form-urlencoded", b"token=" + b"a" * (MAX_TOKEN + 1)),
    ("application/json", b'{"token": "tsm1.a.b", "pad": "' + b"a" * MAX_BODY + b'"}'),
    ("application/x-www-form-urlencoded", b"token"),
])
def test_extract_token_turns_hostile_bodies_into_malformed(content_type, body):
    with pytest.raises(TailismanError) as caught:
        extract_token(content_type, body)
    assert caught.value.code == ErrorCode.MALFORMED


def test_extract_token_accepts_a_token_at_the_length_cap():
    assert extract_token("application/json", b'{"token": "' + b"a" * MAX_TOKEN + b'"}') == "a" * MAX_TOKEN


@pytest.mark.parametrize("leeway", [-1, 1.5, True])
def test_leeway_must_be_a_non_negative_integer(leeway):
    with pytest.raises(ValueError):
        verifier(leeway=leeway)
