from antios.dashboard import main


def test_dashboard_self_test_does_not_open_window():
    assert main(["--self-test"]) == 0
