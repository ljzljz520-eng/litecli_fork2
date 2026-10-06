"""Capability declarations in the special command registry."""

import os

import pytest

from litecli.main import LiteCli
from litecli.packages import special  # noqa: F401  (ensures commands register)
from litecli.packages.guard import capabilities as caps
from litecli.packages.special.main import COMMANDS, command_capabilities

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEST_CONFIG = os.path.join(_PROJECT_DIR, "tests", "liteclirc")


@pytest.fixture(scope="module")
def litecli_with_dynamic_commands():
    # .read/.open are registered by LiteCli.register_special_commands().
    return LiteCli(liteclirc=_TEST_CONFIG)


def test_declared_command_capabilities(litecli_with_dynamic_commands):
    expected = {
        "system": {caps.PROCESS},
        "pager": {caps.PROCESS},
        "\\pipe_once": {caps.PROCESS},
        "\\e": {caps.PROCESS, caps.FILESYSTEM},
        ".output": {caps.FILESYSTEM},
        "tee": {caps.FILESYSTEM},
        ".once": {caps.FILESYSTEM},
        "\\o": {caps.FILESYSTEM},
        ".read": {caps.FILESYSTEM},
        "source": {caps.FILESYSTEM},
        ".open": {caps.FILESYSTEM},
        "use": {caps.FILESYSTEM},
        ".load": {caps.EXTENSION},
        ".import": {caps.FILESYSTEM, caps.WRITE_DATA},
    }
    for command, want in expected.items():
        assert command_capabilities(command) == frozenset(want), command


def test_llm_command_capabilities():
    # Registered only when the llm package is importable; capability must be
    # present whenever the command exists.
    llm = command_capabilities("\\llm")
    if llm:
        assert llm == frozenset({caps.PROCESS, caps.NETWORK})


def test_aliases_inherit_capabilities(litecli_with_dynamic_commands):
    assert command_capabilities("\\.") == frozenset({caps.FILESYSTEM})
    assert command_capabilities("\\|") == frozenset({caps.PROCESS})
    assert command_capabilities("\\u") == frozenset({caps.FILESYSTEM})


def test_undeclared_commands_have_empty_capabilities():
    assert command_capabilities(".tables") == frozenset()
    assert command_capabilities(".databases") == frozenset()
    assert command_capabilities("help") == frozenset()
    assert command_capabilities("not-a-command") == frozenset()


def test_all_declared_capabilities_are_known():
    for command, spec in COMMANDS.items():
        assert spec.capabilities <= caps.ALL_CAPABILITIES, command
