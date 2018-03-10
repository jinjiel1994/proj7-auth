from acp_times import open_time, close_time
import nose  # Testing framework
import logging
import arrow

logging.basicConfig(format='%(levelname)s:%(message)s',
                    level=logging.WARNING)
log = logging.getLogger(__name__)


def test_open_time():
    # Distance = 200
    assert open_time(0.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T08:00:00+00:00"
    assert open_time(100.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T10:56:00+00:00"
    assert open_time(200.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T13:53:00+00:00"
    assert open_time(250.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T15:27:00+00:00"

    # Distance = 1000
    assert open_time(0.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T08:00:00+00:00"
    assert open_time(200.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T13:53:00+00:00"
    assert open_time(400.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T20:08:00+00:00"
    assert open_time(600.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T02:48:00+00:00"
    assert open_time(800.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T09:57:00+00:00"
    assert open_time(900.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T13:31:00+00:00"
    assert open_time(1000.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T17:05:00+00:00"


def test_close_time():
    # Distance = 200
    assert close_time(0.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T08:00:00+00:00"
    assert close_time(100.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T14:40:00+00:00"
    assert close_time(200.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T21:20:00+00:00"
    assert close_time(250.0, 200, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T00:40:00+00:00"

    # Distance = 1000
    assert close_time(0.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T08:00:00+00:00"
    assert close_time(200.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-01T21:20:00+00:00"
    assert close_time(400.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-02T10:40:00+00:00"
    assert close_time(600.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-03T00:00:00+00:00"
    assert close_time(800.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-03T17:30:00+00:00"
    assert close_time(900.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-04T02:15:00+00:00"
    assert close_time(1000.0, 1000, arrow.get("2017-01-01T08:00:00+00:00")) == "2017-01-04T11:00:00+00:00"
