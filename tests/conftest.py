'''Shared pytest fixtures.

Test fixtures under fixtures/ are synthetic - shaped to match real API
responses this package has been verified against live hardware for
(see the docstrings in src/ubnt_automata/*.py and the project's commit
history), but with fabricated hostnames/coordinates/MACs rather than
real captured data, since this is a public repository.
'''
import json
import pathlib

import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / 'fixtures'


@pytest.fixture
def load_json():
    '''Factory fixture: load_json('name.json') -> parsed JSON.'''
    def _load(name):
        with open(FIXTURES_DIR / name, encoding='utf-8') as fh:
            return json.load(fh)
    return _load


@pytest.fixture
def load_text():
    '''Factory fixture: load_text('name.txt') -> raw file contents.'''
    def _load(name):
        with open(FIXTURES_DIR / name, encoding='utf-8') as fh:
            return fh.read()
    return _load
