from .ExecutableFormat import ExecutableFormat

from macholib import mach_o
from macholib.MachO import MachO
from macholib.SymbolTable import SymbolTable


class MachOLib(ExecutableFormat):
	"""Not implemented yet, use LIEF"""

	bitnessMapping = {mach_o.mach_header_64: 64, mach_o.mach_header: 32}

	def __child_enter__(self):
		self.machOFile = MachO(self.source)
		self.bitness = bitnessMapping[self.machOFile.headers[0].mach_header]

	def findSymbol(self, name):
		raise NotImplementedError()

	def findVA(self, name):
		raise NotImplementedError()

	def raw2Offset(self, raw):
		raise NotImplementedError()
