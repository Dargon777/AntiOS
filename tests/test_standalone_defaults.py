from antios.cli import build_parser


def test_virus_scan_defaults_to_standalone_clamav():
    args = build_parser().parse_args(["virus-scan", "fixture"])
    assert args.engine == "clamav"


def test_quarantine_defaults_to_standalone_clamav():
    args = build_parser().parse_args(["quarantine", "add", "fixture"])
    assert args.engine == "clamav"


def test_amsi_remains_explicit_compatibility_mode():
    args = build_parser().parse_args(["virus-scan", "fixture", "--engine", "amsi"])
    assert args.engine == "amsi"
