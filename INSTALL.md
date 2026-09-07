# Installation


## Pip

### Local development

Windows:
```
git clone https://github.com/dmcken/ubnt_automata.git
cd <git root dir>
python -m pip install -e .
```

Unix:
```
git clone https://github.com/dmcken/ubnt_automata.git
cd <git root dir>
python3 -m pip install --upgrade .
```

### Git

```
pip install git+https://github.com/dmcken/ubnt_automata.git
```

This tracks the default branch, which moves as new commits land - fine
for local testing, but Docker builds and other downstream consumers
should pin to a released tag instead so builds don't silently change
underneath them:

```
pip install git+https://github.com/dmcken/ubnt_automata.git@v0.2.0
```

Available tags: https://github.com/dmcken/ubnt_automata/tags

### Pypi

Not published yet.
