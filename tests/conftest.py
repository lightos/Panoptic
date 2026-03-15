"""Shared test fixtures for Panoptic tests."""

import pytest


@pytest.fixture
def sample_passwd() -> str:
    """Sample /etc/passwd content for parser tests."""
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "user:x:1000:1000:Test User:/home/user:/bin/bash\n"
    )
