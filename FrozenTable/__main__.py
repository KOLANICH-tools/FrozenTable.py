from pprint import pprint
import sys
from os import isatty
from os.path import sep as pathSep

from . import FrozenTable
import mmap
from plumbum import cli
from pathlib import Path
import string

from random import shuffle, choice
import marshal


class FrozenTableCLI(cli.Application):
	"""Tools to manipulate frozen table in python37.dll"""


@FrozenTableCLI.subcommand("remove")
class FrozenTableRemoveCLI(cli.Application):
	"""Removes from the passed symbols from the frozen table."""

	def main(self, file: cli.ExistingFile, *symbols2remove):
		if not symbols2remove:
			symbols2remove = ("_frozen_importlib_external",)

		with FrozenTable(file) as t:
			t.remove(symbols2remove)
			t.writeTable()


def decompile2Str(code):
	import uncompyle6
	from io import StringIO

	with StringIO() as s:
		uncompyle6.code_deparse(code, out=s)
		return s.getvalue()


@FrozenTableCLI.subcommand("dump")
class FrozenTableDumpCLI(cli.Application):
	"""Dumps content of frozen table"""

	unmarshal = cli.Flag("--unmarshal", help="unmarshal the stuff. INSECURE")
	decompile = cli.Flag("--decompile", help="decompile the stuff. Requires `uncompyle6` package", requires=["--unmarshal"])

	def main(self, file: cli.ExistingFile, symbol2dump=None):
		if symbol2dump:
			with FrozenTable(file) as t: # unmarshalling only the needed symbol
				s = t[symbol2dump]
				res = s.code
				if self.unmarshal:
					res = marshal.loads(res)
					if self.decompile:
						res = decompile2Str(res)

				
				sys.stdout.flush()

				if isinstance(res, bytes):
					sys.stdout.buffer.write(res)
				elif isinstance(res, str):
					print(res, file=sys.stdout)
				else:
					pprint(res, stream=sys.stdout)

				sys.stdout.flush()
		else:
			with FrozenTable(file, unmarshal=self.unmarshal) as t:
				if self.decompile:
					for s in t:
						s.decompiled = decompile2Str(s.obj)

				pprint(t.dict, stream=sys.stderr)


@FrozenTableCLI.subcommand("reorder")
class FrozenTableReorderCLI(cli.Application):
	"""Reorders records in the frozen table."""

	def main(self, file: cli.ExistingFile, *newOrder):
		with FrozenTable(file) as t:
			if not newOrder:
				newOrder = list(t.keys())
				shuffle(newOrder)
			t.reorder(newOrder)
			t.writeTable()


def randStrGen(len, alph):
	for i in range(len):
		yield choice(alph)


def randStr(len, alph: str = string.ascii_uppercase + string.ascii_lowercase):
	return "".join(randStrGen(len, alph))


templatesDir = Path(__file__).parent / "templates"


@FrozenTableCLI.subcommand("make_redirector")
class MakeFrozenModuleRedirectorCLI(cli.Application):
	"""Creates a module, using the implementation from the file instead of it."""

	@classmethod
	def pathFromModuleName(cls, moduleName: str):
		moduleNameSplit = moduleName.split(".")
		for prefix in sys.path:
			p = Path(prefix)
			for pc in moduleNameSplit[:-1]:
				p = p / pc

			p = p / (moduleNameSplit[-1] + ".py")
			p = p.absolute()
			if p.exists():
				return p

	def main(self, moduleNameOrPath: str):
		if "/" in moduleNameOrPath or pathSep in moduleNameOrPath:
			modulePath = Path(moduleNameOrPath)
			moduleName = None
		else:
			moduleName = moduleNameOrPath
			modulePath = self.__class__.pathFromModuleName(moduleName)

		if moduleName == "importlib._bootstrap" or moduleName == "importlib._bootstrap_external":
			varName = "f"#it is inside a function, no need to randomize in order to prevent collisions
		else:
			varName = "__" + randStr(126)

		#using `ast` for may be a more correct solution, but readability will obviously be hurt
		code = (templatesDir / "$common.py.tmpl").read_text().format(varName=varName, filePath=repr(str(modulePath)))

		if moduleName == "importlib._bootstrap" or moduleName == "importlib._bootstrap_external":
			code = (templatesDir / (moduleName + ".py.tmpl")).read_text().format(common=code.replace("\n", "\n\t"))

		print(code, file=sys.stderr)
		sys.stderr.flush()

		sys.stdout.flush()
		sys.stdout.buffer.write(marshal.dumps(compile(code, modulePath.name, "exec")))
		sys.stdout.flush()


@FrozenTableCLI.subcommand("replace")
class FrozenTableReplaceCLI(cli.Application):
	"""Replaces contents of a frozen module."""

	def main(self, file: cli.ExistingFile, name: str = "_frozen_importlib", valueFile: str = None):
		if valueFile is None:
			if not isatty(sys.stdin.fileno()):
				code = sys.stdin.buffer.read()
			else:
				raise ValueError("Either provide the path of file with `marshal`ed bytecode or pipe it!")
		else:
			code = Path(valueFile).read_bytes()

		with FrozenTable(file) as t:
			t.modifyEntry(name, code)
			t.writeTable()


if __name__ == "__main__":
	FrozenTableCLI.run()
