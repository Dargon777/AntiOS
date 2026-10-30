from antios.logging_utils import configure_logging


def test_logging_can_be_disabled():
    logger = configure_logging("INFO", "")
    assert logger.handlers
    assert logger.propagate is False


def test_reconfiguring_logging_closes_previous_file_handler(tmp_path):
    logger = configure_logging(file_path=str(tmp_path / "old.log"))
    old_handler = logger.handlers[0]
    old_stream = old_handler.stream
    try:
        configure_logging(file_path=str(tmp_path / "new.log"))
        assert old_stream.closed
    finally:
        old_handler.close()
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
