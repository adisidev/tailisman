import json
import runpy
from pathlib import Path

import pytest

from tailisman import TailismanError, Verifier
from tailisman._token import b64encode, derive_consumer_key, format_key, normalise_origin

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "testdata" / "vectors.json").read_text())


def test_committed_vectors_match_regeneration():
    generator = runpy.run_path(str(ROOT / "scripts" / "make_vectors.py"))
    assert (ROOT / "testdata" / "vectors.json").read_text() == generator["render"]()


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vector(case):
    verifier = Verifier(key=case["key"], audience=case["audience"], clock=lambda: VECTORS["now"], leeway=VECTORS["leeway"])
    if case["expect"].get("ok"):
        assert vars(verifier.verify(case["token"])) == case["expect"]["claim"]
    else:
        with pytest.raises(TailismanError) as caught:
            verifier.verify(case["token"])
        assert caught.value.code == case["expect"]["code"]


@pytest.mark.parametrize("case", VECTORS["origins"], ids=lambda c: c["input"] or "empty")
def test_origin_normalisation(case):
    if case["expect"] is None:
        with pytest.raises(ValueError):
            normalise_origin(case["input"])
    else:
        assert normalise_origin(case["input"]) == case["expect"]


def test_consumer_keys_derive_from_master():
    import base64

    master = base64.urlsafe_b64decode(VECTORS["master"] + "=")
    for origin, key in VECTORS["keys"].items():
        assert format_key(derive_consumer_key(master, origin)) == key
    assert b64encode(master) == VECTORS["master"]
