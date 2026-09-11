"""Two-tier tests: quick (default) vs long (--runslow).

Quick CI  : `pytest`               -> fast unit tests only (FIPS vectors, schedule
                                       inversion, mode mapping) -- seconds, no hardware.
Long/full : `pytest --runslow`     -> also the ~25s/scan synthetic recoveries and
                                       the replay of captured trace vectors in
                                       tests/vectors/*.npz.
"""
import pytest


def pytest_addoption(parser):
    parser.addoption("--runslow", action="store_true", default=False,
                     help="run slow tests (engine scans + vector replays)")


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: slow test (engine scan / vector replay)")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runslow"):
        return
    skip = pytest.mark.skip(reason="need --runslow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)
