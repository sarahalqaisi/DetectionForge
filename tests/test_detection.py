from app.services.detection import match_event, parse_rule


def test_regex_rule_matches():
    rule = parse_rule('''
title: PowerShell Test
detection:
  selection:
    event_type: process_create
    command_line|regex: "(?i)(-enc|-encodedcommand)"
  condition: selection
''')
    assert match_event(rule, {"event_type": "process_create", "command_line": "powershell -EncodedCommand AAA"})
    assert not match_event(rule, {"event_type": "process_create", "command_line": "cmd /c whoami"})


def test_list_rule_matches():
    rule = parse_rule('''
title: Severity Test
detection:
  selection:
    severity: [high, critical]
  condition: selection
''')
    assert match_event(rule, {"severity": "high"})
