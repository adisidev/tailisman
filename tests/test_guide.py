import pytest

from tailisman import guide
from tailisman.cli import main


@pytest.mark.parametrize("topic", sorted(guide.TOPICS))
def test_every_topic_prints_its_part_of_the_guide(capsys, topic):
    assert main(["guide", topic]) == 0
    _, _, heading = guide.TOPICS[topic]
    out = capsys.readouterr().out
    assert out.startswith(heading + "\n" if heading else "") and len(out) > 500


def test_the_share_topic_is_the_share_section_alone(capsys):
    main(["guide", "share"])
    out = capsys.readouterr().out
    assert "tailisman share https://notes.example.com/reports/ --to alice" in out and "| 7 |" in out
    assert "## What can go wrong" not in out and "## 1." not in out


def test_help_starts_with_the_guide(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert capsys.readouterr().out.startswith("usage: tailisman guide [TOPIC]   (start here")
