from ..ExecutableFormat import ExecutableFormat
import typing
import pefile
from pefile import PE


class PEFile(ExecutableFormat):
	bitnessMapping = None

	@classmethod
	def initClass(cls) -> None:
		cls.bitnessMapping = {pefile.OPTIONAL_HEADER_MAGIC_PE: 32, pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS: 64}

	def __child_enter__(self) -> None:
		self.lib = PE(data=self.map)
		self.bitness = self.__class__.bitnessMapping[self.lib.PE_TYPE]

	@property
	def imageBase(self) -> int:
		return self.lib.OPTIONAL_HEADER.ImageBase

	def findVA(self, name:str) -> typing.Optional[int]:
		"""Gets a symbol addr from PE export table"""
		name = name.encode("ascii")
		for exp in self.lib.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name == name:
				return exp.address + self.imageBase

	def raw2Offset(self, raw:int) -> int:
		return self.RVA2Offset(self.raw2RVA(raw))

	def RVA2Offset(self, rva:int) -> int:
		return self.lib.get_offset_from_rva(rva)

	def offset2RVA(self, offset:int) -> int:
		return self.lib.get_rva_from_offset(offset)

	def RVA2Raw(self, RVA:int) -> int:
		return self.imageBase + RVA

	def raw2RVA(self, raw: int) -> int:
		return raw - self.imageBase

	def offset2Raw(self, offset:int) -> int:
		return self.RVA2Raw(self.offset2RVA(offset))
