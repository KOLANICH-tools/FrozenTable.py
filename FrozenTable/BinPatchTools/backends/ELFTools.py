from ..ExecutableFormat import ExecutableFormat
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from ELFRelocs import RelocWrapper, Relocator
from ELFMachine import ELFMachine
import typing

RelocEnumT = typing.Union[typing.Type["ELFRelocs.relocEnums.ELF_I686_RELOCS"], typing.Type["ELFRelocs.relocEnums.ELF_AMD64_RELOCS"], ]

from elftools.elf.relocation import Relocation
from elftools.elf.sections import Symbol, SymbolTableSection

LookupResultT = typing.Tuple[int, Symbol]

def crawlSymbolTable(symbolTable: SymbolTableSection, predicate: typing.Callable) -> typing.Optional[LookupResultT]:
	for nSym, symbol in enumerate(symbolTable.iter_symbols()):
		if predicate(symbol):
			return (nSym, symbol)


class ELFToolsRelocWrapper(RelocWrapper):
	def __init__(self, reloc: Relocation, table: RelocEnumT, symbol: Symbol) -> None:
		self._reloc = reloc
		self.type = table(reloc.entry["r_info_type"])
		self.symbol = symbol

	@property
	def offset(self) -> int:
		return self._reloc.entry["r_offset"]

	@property
	def addend(self) -> int:
		return self._reloc.entry["r_addend"]

	@property
	def symbol_value(self) -> int:
		return self.symbol.entry["st_value"]


class ELFToolsRelocator(Relocator):
	def __init__(self, parent: "ELFTools") -> None:
		arch = parent.elfFile.header.e_machine
		if not arch[3].isdigit():
			arch = arch[3:]
		arch = getattr(ELFMachine, arch)
		
		super().__init__(arch)
		self.parent = parent

	@property
	def B(self) -> int:
		return self.parent.imageBase

	def relocFromPointerRawAddr(self, raw: int) -> RelocWrapper:
		backendReloc = self.parent.findRelocByRaw(raw)
		if backendReloc:
			return ELFToolsRelocWrapper(backendReloc, self.table, self.parent.findSymbolByIndex(backendReloc.entry["r_info_sym"]))


class ELFTools(ExecutableFormat):
	bitnessMapping = { "ELFCLASS" + str(b): b for b in (32, 64) }

	def __child_enter__(self) -> "ELFTools":
		self.elfFile = ELFFile(self._fd)
		#print("machine:", mach)

		self.relocator = ELFToolsRelocator(self)

		self.symbolTables = [s for s in self.elfFile.iter_sections() if isinstance(s, SymbolTableSection)]
		self.PT_LOAD_Segments = [s for s in list(self.elfFile.iter_segments()) if s["p_type"] == "PT_LOAD"]
		self.imageBase = self.findBase()

		self.relocationTables = [s for s in self.elfFile.iter_sections() if s.name == ".rel.plt" or s.name == ".rela.plt"]
		self.relDyn = [s for s in self.elfFile.iter_sections() if s.name == ".rel.dyn" or s.name == ".rela.dyn"]
		self.relCombined = [*self.relocationTables, *self.relDyn]

		self.bitness = self.__class__.bitnessMapping[self.elfFile.header.e_ident.EI_CLASS]

		return self

	def resolvePtr(self, ptrValue:int, ptrRawVirtualAddr:int) -> int:
		return self.relocator.computeRelocatedPtr(ptrRawVirtualAddr, ptrValue)[1]

	def findSymbolByPredicate(self, predicate: typing.Callable) -> typing.Optional[LookupResultT]:
		for symbolTable in self.symbolTables:
			res=crawlSymbolTable(symbolTable, predicate)
			if res:
				return res

	def findSymbolByName(self, name:str) -> typing.Optional[LookupResultT]:
		return self.findSymbolByPredicate(lambda s: s.name == name)

	def findSymbolByAddr(self, raw:int):
		return self.findSymbolByPredicate(lambda s: s.entry.st_value == raw)

	def findSymbolByIndex(self, index:int) -> Symbol:
		for symbolTable in self.symbolTables:
			s = symbolTable.get_symbol(index)
			if s:
				return s

	def findRelocByIndex(self, nSym:int):
		for relT in self.relCombined:
			reloc = relT.get_relocation(nSym)
			if reloc:
				break
		return reloc

	def findRelocByOffset(self, offset:int):
		return self.findRelocByRaw(offset2Raw(offset))

	def findRelocByRaw(self, raw:int) -> typing.Optional[Relocation]:
		for relT in self.relCombined:
			for rel in relT.iter_relocations():
				if rel.entry["r_offset"] == raw:#under offset here raw virtual addr is meant, not offset in the file. :(
					return rel

	def findBase(self) -> int:
		"""finds image base - the virtual addr of the first LOAD header"""
		return self.PT_LOAD_Segments[0].header["p_vaddr"]

	def findVA(self, name:str) -> int:
		"""Gets a symbol addr from ELF export table"""
		(nSym, symbol) = self.findSymbolByName(name)
		return symbol.entry["st_value"]

	def crawlSegmentsTable(self, addr1:int, ofs1:str = "p_vaddr", sz1: str = "p_memsz", ofs2: str = "p_offset", sz2: str = "p_filesz") -> int:
		for s in self.PT_LOAD_Segments:
			endAddr = s.header[ofs1] + s.header[sz1]
			#print(addr1)
			#print(s.header[ofs1], " <= addr1 < ", endAddr, s.header[ofs1] <= addr1, addr1 < endAddr)
			if s.header[ofs1] <= addr1 < endAddr:
				rOffset = addr1 - s.header[ofs1]
				if rOffset < s.header[sz2]:
					return s.header[ofs2] + rOffset

	def raw2Offset(self, raw:int) -> int:
		return self.crawlSegmentsTable(raw, "p_vaddr", "p_memsz", "p_offset", "p_filesz")

	def offset2Raw(self, offset:int) -> int:
		return self.crawlSegmentsTable(offset, "p_offset", "p_filesz", "p_vaddr", "p_memsz")
