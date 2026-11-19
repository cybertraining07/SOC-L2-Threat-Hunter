from app.collectors.linux_auth_collector import parse_auth_line


def test_parse_failed_ssh_login():
    line = (
        "Nov 19 02:20:48 kali sshd-session[216362]: "
        "Failed password for invalid user testuser "
        "from 127.0.0.1 port 43538 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["event_type"] == "FAILED_LOGIN"
    assert event["username"] == "testuser"
    assert event["source_ip"] == "127.0.0.1"
    assert event["severity"] == "MEDIUM"


def test_parse_successful_ssh_login():
    line = (
        "Nov 19 02:21:00 kali sshd[1234]: "
        "Accepted password for kali from 127.0.0.1 "
        "port 43540 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["event_type"] == "SUCCESSFUL_LOGIN"
    assert event["username"] == "kali"
    assert event["source_ip"] == "127.0.0.1"


def test_parse_invalid_ssh_user():
    line = (
        "Nov 19 02:19:53 kali sshd-session[216362]: "
        "Invalid user unknownuser from 127.0.0.1 port 43538"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["event_type"] == "INVALID_USER"
    assert event["username"] == "unknownuser"
    assert event["source_ip"] == "127.0.0.1"


def test_ignore_non_ssh_log():
    line = (
        "Nov 19 02:22:00 kali CRON[1234]: "
        "pam_unix(cron:session): session opened"
    )

    assert parse_auth_line(line) is None


def test_event_contains_original_log_line():
    line = (
        "Nov 19 02:20:48 kali sshd-session[216362]: "
        "Failed password for testuser from 127.0.0.1 "
        "port 43538 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["raw_data"]["original_line"] == line
    assert event["source"] == "Linux Authentication Log"
