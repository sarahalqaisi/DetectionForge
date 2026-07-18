from app.services.normalizers import normalize_text


def test_linux_auth_normalization():
    content = "Jul 19 10:00:01 host sshd[1]: Failed password for root from 203.0.113.10 port 50000 ssh2"
    events = normalize_text(content, "linux_auth")
    assert len(events) == 1
    assert events[0]["event_type"] == "failed_login"
    assert events[0]["source_ip"] == "203.0.113.10"


def test_nginx_traversal_normalization():
    content = '203.0.113.5 - - [19/Jul/2026:10:10:12 +0000] "GET /../../etc/passwd HTTP/1.1" 400 166 "-" "curl"'
    events = normalize_text(content, "nginx")
    assert events[0]["event_type"] == "directory_traversal"
    assert events[0]["severity"] == "high"


def test_suricata_json_normalization():
    content = '{"timestamp":"2026-07-19T10:30:00Z","event_type":"alert","src_ip":"203.0.113.77","dest_ip":"10.0.0.5","alert":{"signature":"Test","severity":2}}'
    events = normalize_text(content, "suricata")
    assert events[0]["source"] == "suricata"
    assert events[0]["severity"] == "high"
