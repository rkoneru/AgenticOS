from __future__ import annotations

import pytest
from axis_sdk import SseParser


def feed(*chunks: str) -> tuple[SseParser, list[tuple[str, str, str]]]:
    p = SseParser()
    return p, [(e.event, e.data, e.id) for c in chunks for e in p.push(c)]


def test_simple_event() -> None:
    assert feed("data: hi\n\n")[1] == [("message", "hi", "")]


def test_every_split_point_gives_the_same_events() -> None:
    text = 'id: 7\nevent: run_event\ndata: {"a":1}\ndata: second\n\n: keepalive\n\ndata: x\r\n\r\n'
    whole = feed(text)[1]
    assert len(whole) == 2
    for i in range(1, len(text)):
        assert feed(text[:i], text[i:])[1] == whole


def test_multiline_data_and_space_rule() -> None:
    assert feed("data:  a\ndata\ndata: c\n\n")[1][0][1] == " a\n\nc"


def test_comments_unknown_fields_and_blank_events_are_ignored() -> None:
    assert feed(": ping\nfoo: bar\n\n\n")[1] == []


def test_line_endings() -> None:
    assert feed("data: a\r", "\ndata: b\r\r")[1] == [("message", "a\nb", "")]
    assert feed("data: a\rdata: b\r\r")[1][0][1] == "a\nb"


def test_bom_only_at_start() -> None:
    assert feed("﻿data: a\n\n")[1][0][1] == "a"
    assert len(feed("data: a\n\n﻿data: b\n\n")[1]) == 1


def test_last_event_id_persists_and_nul_ids_are_ignored() -> None:
    p, out = feed("id: 1\ndata: a\n\ndata: b\n\nid: 2\x003\ndata: c\n\n")
    assert [e[2] for e in out] == ["1", "1", "1"]
    assert p.last_event_id == "1"


@pytest.mark.parametrize(
    ("text", "expected"), [("retry: 2500\n\n", 2500), ("retry: soon\n\n", None)]
)
def test_retry_only_when_numeric(text: str, expected: int | None) -> None:
    assert feed(text)[0].retry == expected


def test_unterminated_final_event_is_discarded() -> None:
    p = SseParser()
    assert p.push("data: partial") == []
    p.end()
    assert p.push("\n\n") == []


def test_field_without_colon() -> None:
    assert feed("data\n\n")[1][0][1] == ""
