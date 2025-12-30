import sys

import pytest
from logurich import rich_set_console
from rich.console import Console


@pytest.fixture(autouse=True, scope="session")
def configure_loguru_rich_for_pytest():
    # Create console AFTER pytest has installed its capture,
    # and bind it explicitly to sys.stderr (the captured one)
    console = Console(file=sys.stderr, markup=True, force_terminal=True)

    # Inject it into your app's console module
    rich_set_console(console)
