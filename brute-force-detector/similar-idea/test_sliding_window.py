from datetime import UTC, datetime, timedelta

import pytest
from sliding_window import burst_moments

BASE = datetime(2026, 11, 24, 10, 0, 0, tzinfo=UTC)
WINDOW = timedelta(seconds=60)


def at(*seconds: int) -> list[datetime]:
    """at(0, 10, 20) -> three timestamps 0 s, 10 s, 20 s after BASE."""
    return [BASE + timedelta(seconds=s) for s in seconds]


@pytest.mark.parametrize(
    ("offsets", "expected"),
    [
        pytest.param((0, 10, 20), (20,), id="3 in 20 s -> fires on the 3rd"),
        pytest.param((0, 10), (), id="2 events -> under threshold"),
        pytest.param((0, 30, 60), (60,), id="exactly 60 s apart -> inside (inclusive)"),
        pytest.param((0, 30, 61), (), id="61 s -> first event slid out"),
        pytest.param((0, 1, 2, 3), (2, 3), id="keeps firing -> alert spam"),
        pytest.param(
            (0, 100, 101, 102, 103), (102, 103), id="old event slides out, new burst"
        ),
        pytest.param((50, 55, 65), (65,), id="burst across a minute boundary"),
        pytest.param((0, 1, 2, 70, 71), (2,), id="several old events expire at once"),
    ],
)
def test_burst_moments(offsets: tuple[int, ...], expected: tuple[int, ...]) -> None:
    assert burst_moments(at(*offsets), threshold=3, window=WINDOW) == at(*expected)
