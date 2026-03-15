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


@pytest.fixture
def sample_html_found() -> str:
    """Sample HTML response that contains a found file."""
    return "<html><body>root:x:0:0:root:/root:/bin/bash</body></html>"


@pytest.fixture
def sample_html_not_found() -> str:
    """Sample HTML response for a file not found."""
    return "<html><body><h1>404 Not Found</h1></body></html>"
