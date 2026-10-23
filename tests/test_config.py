import pytest

from tailisman.issuer.config import ConfigError, TcpListen, UnixListen, parse_config


def config(tmp_path, **overrides):
    (tmp_path / "secret").write_bytes(b"\x01" * 32)
    raw = {"secret_file": "secret", "devices": ["laptop"], "audiences": [{"origin": "https://heckle.example.com"}], **overrides}
    return parse_config(raw, base=tmp_path)


def test_defaults(tmp_path):
    parsed = config(tmp_path)
    assert parsed.listen == TcpListen("127.0.0.1", 8470)
    assert parsed.ttl_seconds == 60
    assert parsed.tailscale_bin == "auto"
    audience = parsed.audiences["https://heckle.example.com"]
    assert (audience.devices, audience.users, audience.refuse_automation) == (frozenset({"laptop"}), None, False)


def test_audiences_are_keyed_by_normalised_origin(tmp_path):
    parsed = config(tmp_path, audiences=[{"origin": "HTTPS://Heckle.Example.com:443/"}])
    assert list(parsed.audiences) == ["https://heckle.example.com"]


def test_audience_devices_override_the_default(tmp_path):
    parsed = config(tmp_path, audiences=[{"origin": "https://heckle.example.com", "devices": ["phone"]}])
    assert parsed.audiences["https://heckle.example.com"].devices == frozenset({"phone"})


@pytest.mark.parametrize("listen,expected", [
    ("127.0.0.1:8470", TcpListen("127.0.0.1", 8470)),
    ("127.0.0.2:9000", TcpListen("127.0.0.2", 9000)),
    ("[::1]:8470", TcpListen("::1", 8470)),
    ("unix:/run/tailisman.sock", UnixListen("/run/tailisman.sock")),
])
def test_loopback_and_unix_listen_accepted(tmp_path, listen, expected):
    assert config(tmp_path, listen=listen).listen == expected


@pytest.mark.parametrize("listen", ["0.0.0.0:8470", "192.0.2.1:8470", "192.168.1.2:8470", "localhost:8470", "[::]:8470", "8470", "127.0.0.1:0", "unix:relative.sock"])
def test_non_loopback_listen_refused(tmp_path, listen):
    with pytest.raises(ConfigError):
        config(tmp_path, listen=listen)


@pytest.mark.parametrize("origin", ["https://heckle.example.com/app", "heckle.example.com", "https://heckle.example.com?x=1", "ftp://heckle.example.com"])
def test_bad_origin_refused(tmp_path, origin):
    with pytest.raises(ConfigError):
        config(tmp_path, audiences=[{"origin": origin}])


@pytest.mark.parametrize("overrides", [
    {"audiences": []},
    {"audiences": [{"origin": "https://a.example.com"}, {"origin": "HTTPS://a.example.com"}]},
    {"devices": []},
    {"audiences": [{"origin": "https://heckle.example.com", "users": []}]},
    {"audiences": [{"origin": "https://heckle.example.com", "refuse_automation": "yes"}]},
    {"audiences": [{"origin": "https://heckle.example.com", "colour": "blue"}]},
    {"ttl_seconds": 3600},
    {"ttl_seconds": "60"},
    {"listen": 8470},
    {"tailscale_bin": ""},
    {"unknown": 1},
])
def test_invalid_configs_refused(tmp_path, overrides):
    with pytest.raises(ConfigError):
        config(tmp_path, **overrides)


def test_secret_must_be_32_bytes(tmp_path):
    (tmp_path / "short").write_bytes(b"x" * 16)
    with pytest.raises(ConfigError):
        config(tmp_path, secret_file="short")
    with pytest.raises(ConfigError):
        config(tmp_path, secret_file="missing")
