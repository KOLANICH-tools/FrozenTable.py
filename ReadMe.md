FrozenTable.py [![Unlicensed work](https://raw.githubusercontent.com/unlicense/unlicense.org/master/static/favicon.png)](https://unlicense.org/)
===============
~~[wheel](https://gitlab.com/KOLANICH/FrozenTable.py/-/jobs/artifacts/master/raw/wheels/FrozenTable.py-0.CI-py3-none-any.whl?job=build)~~
[![PyPi Status](https://img.shields.io/pypi/v/FrozenTable.py.svg)](https://pypi.python.org/pypi/FrozenTable.py)
~~[![GitLab Build Status](https://gitlab.com/KOLANICH/FrozenTable.py/badges/master/pipeline.svg)](https://gitlab.com/KOLANICH/FrozenTable.py/pipelines/master/latest)~~
~~![GitLab Coverage](https://gitlab.com/KOLANICH/FrozenTable.py/badges/master/coverage.svg)~~
[![Libraries.io Status](https://img.shields.io/librariesio/github/KOLANICH/FrozenTable.py.svg)](https://libraries.io/github/KOLANICH/FrozenTable.py)
[![Code style: antiflash](https://img.shields.io/badge/code%20style-antiflash-FFF.svg)](https://codeberg.org/KOLANICH-tools/antiflash.py)

Doxygen-generated docs [are available](https://kolanich.gitlab.io/FrozenTable.py).

Why?
----

Some python modules are baked into the cpython interpreter shared library (`python<version>.dll` on Windows). This shared library contains a symbol [`PyImport_FrozenModules`, which points to](https://github.com/python/cpython/blob/8c77b8cb9188165a123f2512026e3629bf03dc9b/Python/frozen.c#L50) [`_PyImport_FrozenModules`](https://github.com/python/cpython/blob/8c77b8cb9188165a123f2512026e3629bf03dc9b/Python/frozen.c#L31L45), which is a table of [`_frozen`](https://github.com/python/cpython/blob/0a28f8d379544eee897979da0ce99f0b449b49dd/Include/cpython/import.h#L37L41), associating pointers to [`marshal`ed](https://docs.python.org/3/library/marshal.html) [`bytecode`s](https://docs.python.org/3/library/dis.html) of python modules (and objects) to their `name`s.

When an interpreter imports a module, import machinery searches it first in this table. It is possible to disable this behavior, but some lookups are hardcoded into the interpreter and called during interpreter initialization. So you may want to replace the implementations there with own ones.

Use cases
---------

Doing this is useful when you are debugging an own import machinery, but it doesn't work fine and spits weird errors, so you have to add some the debug output into `importlib` itself. But you will be surprised to see that your added code doesn't work. It turns out that part of importing machinery is baked into the table of frozen modules and is always imported from there.

This project provides a solution. With the help of this module you can:

Features
--------
* using `make_redirector` subcommand generate small stubs reading the needed files from disk and executing them and replace the frozen;
* `replace` the entries in the frozen table with the stubs

Also you can
* `list` the entries in the frozen table.
* `reorder` the entries.
* `remove` an entry from the frozen table.
* `dump` an entry from the frozen table.

And of course all the features are available via API.


Usage
-----

```python
from FrozenTable import FrozenTable
from pprint import pprint
import mmap

with FrozenTable("./python37.dll") as t:
	pprint(t.dict)
	t.modifyEntry("__hello__", code)
	t.remove(("__hello__",))  # removes packages from the table, gets an itera(tor|ble)
	
	newOrder=list(t.keys())
	shuffle(newOrder)
	t.reorder(newOrder)  # shuffles the table. Should do no effect.
	t.writeTable() # you need to do it after all your actions
```

Command line interface (CLI)
----------------------------

The lib has a command line interface. Use

```bash
python -m FrozenTable
```

for getting help.

### TL;DR

```bash
python -m FrozenTable make_redirector importlib._bootstrap | python -m FrozenTable replace python3.7
python -m FrozenTable make_redirector importlib._bootstrap_external | python -m FrozenTable replace python37.dll _frozen_importlib_external
```

to patch your python interpreter to use `importlib._bootstrap` from file.


Requirements
------------
* [`kaitaistruct`](https://github.com/kaitai-io/kaitai_struct_python_runtime)
  [![PyPi Status](https://img.shields.io/pypi/v/kaitaistruct.svg)](https://pypi.python.org/pypi/kaitaistruct)
  ![License](https://img.shields.io/github/license/kaitai-io/kaitai_struct_python_runtime.svg) as a runtime for Kaitai Struct-generated code

* And depending on what files you are going to process:
    * ~~[`lief`](https://github.com/lief-project/LIEF) ![Licence](https://img.shields.io/github/license/lief-project/LIEF.svg) [![PyPi Status](https://img.shields.io/pypi/v/lief.svg)](https://pypi.python.org/pypi/lief) [![CI Build Status](https://img.shields.io/github/actions/workflow/status/lief-project/LIEF/linux-x86-64.yml?branch=master&label=Linux%20x86-64&logo=github)](https://github.com/lief-project/LIEF/actions/workflows/linux-x86-64.yml) [![Libraries.io Status](https://img.shields.io/librariesio/github/lief-project/LIEF.svg)](https://libraries.io/github/lief-project/LIEF) - PE, ELF, Mach-O, fast, written in C++, but takes long to build and creating a package is problematic~~ -  ELF is broken
    
    * [`pefile`](https://github.com/erocarrera/pefile) ![Licence](https://img.shields.io/github/license/erocarrera/pefile.svg) [![PyPi Status](https://img.shields.io/pypi/v/pefile.svg)](https://pypi.python.org/pypi/pefile) [![pefile test](https://github.com/erocarrera/pefile/actions/workflows/tests.yaml/badge.svg)](https://github.com/erocarrera/pefile/actions/workflows/tests.yaml) [![Libraries.io Status](https://img.shields.io/librariesio/github/erocarrera/pefile.svg)](https://libraries.io/github/erocarrera/pefile) - PE

    * [`pyelftools`](https://github.com/eliben/pyelftools) ![Licence](https://img.shields.io/github/license/eliben/pyelftools.svg) [![PyPi Status](https://img.shields.io/pypi/v/pyelftools.svg)](https://pypi.python.org/pypi/pyelftools) [![CI Build Status](https://github.com/eliben/pyelftools/workflows/pyelftools-tests/badge.svg)](https://github.com/eliben/pyelftools/actions) [![Libraries.io Status](https://img.shields.io/librariesio/github/eliben/pyelftools.svg)](https://libraries.io/github/eliben/pyelftools) - ELF
