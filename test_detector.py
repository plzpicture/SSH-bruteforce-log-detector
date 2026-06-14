from detector import parse_failed_login


def test_parse_failed_login():
    line = "Jun 10 10:01:12 ubuntu sshd[1234]: Failed password for root from 192.168.0.10 port 54321 ssh2"

    result = parse_failed_login(line)

    assert result["ip"] == "192.168.0.10"
    assert result["username"] == "root"


def test_ignore_success_login():
    line = "Jun 10 10:05:20 ubuntu sshd[1239]: Accepted password for user1 from 192.168.0.20 port 60123 ssh2"

    result = parse_failed_login(line)

    assert result is None
