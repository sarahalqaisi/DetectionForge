from app.services.detection import match_event, parse_rule


def test_regex_rule_matches():
    rule = parse_rule('''
title: PowerShell Test
id: DF-TST-001
logsource: {category: windows}
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
id: DF-TST-002
logsource: {category: generic}
detection:
  selection:
    severity: [high, critical]
  condition: selection
''')
    assert match_event(rule, {"severity": "high"})


def test_sigma_re_modifier_alias():
    rule = parse_rule('''
title: Regex Alias
id: DF-TST-003
logsource: {category: windows}
detection:
  selection:
    command_line|re: "powershell"
  condition: selection
''')
    assert match_event(rule, {"command_line": "PowerShell.exe"})


def test_nested_raw_data_requires_explicit_path_when_top_level_exists():
    rule = parse_rule('''
title: Nested Event
id: DF-TST-004
logsource: {category: generic}
detection:
  selection:
    raw_data.process.name: evil.exe
  condition: selection
''')
    event = {"process": {"name": "safe.exe"}, "raw_data": {"process": {"name": "evil.exe"}}}
    assert match_event(rule, event)
