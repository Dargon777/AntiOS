from antios.logging_utils import configure_logging


def test_logging_can_be_disabled():
    logger = configure_logging("INFO", "")
    assert logger.handlers
    assert logger.propagate is False
