__all__ = ("FrozenTable",)
from .BinPatchTools import *
import typing
from _io import _IOBase
import typing
import struct
from pathlib import Path
import warnings
import marshal
import mmap
from collections import OrderedDict

from .cpython_frozen_table import *

frozenTablePtrImportName = "PyImport_FrozenModules"
frozenTableImportName = "_" + frozenTablePtrImportName


# from hexdump import hexdump


DictT = OrderedDict


def searchBytesWithinRange(haystack:bytes, needle:bytes, start:int, stop:int) -> typing.List[int]:
	res = []
	found = start
	while True:
		found = haystack.find(needle, found, stop)
		if found == -1:
			break

		if found:
			res.append(found)

		found += 1 # next pos
	return res


class FrozenTable:
	def __init__(self, source: typing.Union[mmap.mmap, Path], unmarshal: bool = False, searchWindowSize: int = 500, intSize:int = 4, paddingSize:int = None) -> None:
		"""
		`source` is the source of a PE file.
		`unmarshal` controls if the tool should unmarshal objects for further analysis.
		`searchWindowSize` controls the neighbourhood to look for pointers to determine padding and pointer sizes
		"""
		ctor = getFormatCtor(source)
		self.format = ctor(source)

		if unmarshal:
			warnings.warn("Uses `marshal` currently -> code execution!")

		self.unmarshal = unmarshal
		self.dict = None
		self.intSize = intSize
		self.paddingSize = paddingSize
		self.searchWindowSize = searchWindowSize

	def __enter__(self) -> "FrozenTable":
		self.format.__enter__()
		self.parse()
		return self

	def __exit__(self, *args, **kwargs) -> None:
		self.format.__exit__(*args, **kwargs)
		self.table = None
		self.dict = None
		self.tableOffset = None

	def findHeuristically(self, searchStrStartOffset:int = 0, searchStrEndOffset:int = -1, searchPtrStartOffset:int = 0, searchPtrEndOffset:int = -1, limit:int = 0, namesBank: typing.Tuple[bytes, bytes, bytes, bytes, bytes, bytes] = (b"__hello__", b"__phello__", b"_frozen_importlib", b"_frozen_importlib_external", b"zipimport", b"__phello__.spam") ) -> typing.Tuple[int, int]:
		"""Tries to heuristically find the table. In order to do it searches the binary for already known strings used as names for sections, then searches for pointers to them in the file. In an ELF file pointers can be rewritten by linker and there are lot of formulas to do it and each reloc, and formulas involve pointers addresses, so I currently know any good way to make it work with ELF correctly. But for some files this works, becaise they have raw virtual addresses in the pointers needed by us."""
		from math import gcd
		f = self.format.map
		addrs = []

		for name in namesBank:
			for nameOfs in searchBytesWithinRange(f, name, searchStrStartOffset, searchStrEndOffset):
				namePtr = self.format.offset2Raw(nameOfs)
				#TODO: bruteforce different relocation modes. Fortunately names are not usually relocated in ELF

				if namePtr:
					namePtrBytes = self.format.ptrPacker.pack(namePtr)
					initialPtrs = searchBytesWithinRange(f, namePtrBytes, searchPtrStartOffset, searchPtrEndOffset)
					if limit and len(initialPtrs) > limit:
						initialPtrs = initialPtrs[:limit]
					addrs.extend(initialPtrs)

		#print(addrs)
		minAddr = min(addrs)
		#print("minAddr", hex(minAddr))
		entrySize = 0
		for addr in addrs:
			entrySize = gcd(entrySize, addr - minAddr)
		#print("entrySize", entrySize)

		return minAddr, entrySize

	def parse(self) -> None:
		"""Parses the table. `source` is either `mmap` or `Path`."""
		tableRaw = None
		entrySize = None

		try:
			tableRaw = self.format.findVA(frozenTableImportName)
			#print("Found from import immediately", hex(tableRaw))
		except BaseException:
			pass

		if not tableRaw:
			try:
				frozenPtrVA = self.format.findVA(frozenTablePtrImportName)
				frozenPtrOffset = self.format.raw2Offset(frozenPtrVA)

				#print("frozenPtrVA: ", hex(frozenPtrVA))
				#print("frozenPtrOffset: ", hex(frozenPtrOffset))

				tableRaw = self.format.parsePtr(frozenPtrOffset)
				#print("Found from import by ptr", hex(tableRaw))

			except BaseException:
				pass

		if not tableRaw:
			try:
				tableRaw, entrySize = self.findHeuristically()
				#print("Found heuristically", hex(tableRaw))
			except BaseException:
				pass

		if not tableRaw:
			raise NotImplementedError("Table has not been found")

		self.tableOffset = self.format.raw2Offset(tableRaw)

		kaitStr = KaitaiStream(BytesIO(self.format.map))

		if self.paddingSize is None:
			if entrySize is None:
				#firstName = self.format.raw2Offset(self.format.parsePtr(self.tableOffset)) # first item of the record is name
				firstName = self.format.resolvePtrByOffset(self.tableOffset) # first item of the record is name
				#print(self.format.map[firstName:firstName+20])
				entrySize = self.findHeuristically(searchPtrStartOffset=self.tableOffset - self.searchWindowSize, searchPtrEndOffset=self.tableOffset + self.searchWindowSize, limit=0)[1]

			intAndPaddingSize = entrySize - 2 * self.format.byteness
			self.paddingSize = intAndPaddingSize - self.intSize

		assert self.paddingSize == 4 or self.paddingSize == 0

		#print("sizeof(int)", self.intSize)
		#print("padding size", self.paddingSize)

		parsed = CpythonFrozenTable(self.format.byteness, self.intSize, self.paddingSize, self.tableOffset, kaitStr)

		for i in range(len(parsed.table) - 1):
			entry = parsed.table[i]
			#print("entry.code_size_and_type", hex(entry.code_size_and_type), entry.code_size_and_type)
			resEl = CpythonFrozenTable.TranslatedEntry(
				code_offset=self.format.raw2Offset(self.format.resolvePtr(
					entry.code_ptr.raw_ptr,
					self.format.offset2Raw(entry.code_ptr._debug["raw_ptr"]["start"])
				)),
				entry=entry,
				name_offset=self.format.raw2Offset(self.format.resolvePtr(
					entry.name_ptr.raw_ptr,
					self.format.offset2Raw(entry.name_ptr._debug["raw_ptr"]["start"])
				)),
				_io=parsed._io, _parent=parsed, _root=parsed._root
			)
			if self.unmarshal:
				resEl.obj = marshal.loads(resEl.code)

			parsed.table[i] = resEl

		self.table = parsed.table

		self.dict = DictT((el.name, el) for el in iter(self))

	def __iter__(self) -> typing.Iterator[CpythonFrozenTable.TranslatedEntry]:
		for el in self.table:
			if isinstance(el, CpythonFrozenTable.TranslatedEntry):
				yield el

	def keys(self):
		return self.dict.keys()

	def values(self):
		return self.dict.values()

	def items(self):
		return self.dict.values()

	def getIntTypeLetter(self) -> str:
		if self.intSize == 4:
			return "i"
		elif self.intSize == 8:
			return "q"
		elif self.intSize == 2:
			return "d"
		else:
			raise ValueError("Unsupported byteness " + str(self.intSize))

	def writeTable(self) -> None:
		"""Constructs and writes the table of pointers from self.dict"""

		offset = self.tableOffset
		#print("tableOffset", hex(self.tableOffset))

		s = struct.Struct(self.format.getPtrTypeLetter() * 2 + self.getIntTypeLetter())

		def writeItem(name_ptr:int, code_ptr:int, code_size:int, is_package:bool=False):
			nonlocal offset
			if is_package:
				code_size *= -1

			data = s.pack(name_ptr, code_ptr, code_size) + b"\0"*self.paddingSize
			newOffset = offset + len(data)
			#print(hexdump(self.format.map[offset:newOffset], "return"), "->", hexdump(data, "return"))

			self.format.map[offset:newOffset] = data
			offset = newOffset

		for entry in self.items():
			writeItem(entry.entry.name_ptr.raw_ptr, entry.entry.code_ptr.raw_ptr, entry.entry.code_size, entry.entry.is_package)

		writeItem(0, 0, 0, False)

	def modifyEntry(self, name:str, code:typing.Union[bytes, bytearray], newName:str = None) -> None:
		"""Modifies the actual data and marshalled objects in place. There must be enough space (the newer code/name should consume less or equal amount of space) for them. First modifies the data, second modifies the items. You need to `writeTable` after that!!!"""

		if newName and len(newName) > len(name):
			raise ValueError("Not enough space for new name")

		el = self[name]

		if len(code) > el.entry.code_size:
			raise ValueError("Not enough space for new code")

		if code is not None:
			el._m_code = code
			el.entry._m_code_size = len(code)
			self.format.map[el.code_offset : (el.code_offset + len(code))] = code

		if newName is not None:
			newNameL = len(newName)
			endNameOffst = el.name_offset + newNameL
			zerosLen = len(name) - newNameL + 1

			self.format.map[el.name_offset : endNameOffst] = newName.encode("ascii")
			self.format.map[endNameOffst : endNameOffst + zerosLen] = b"\0" * zerosLen

			el._m_name = newName
			self.dict[newName] = el
			del (self.dict[name])

	def __getitem__(self, k:str) -> CpythonFrozenTable.TranslatedEntry:
		return self.dict[k]

	def __contains__(self, k:str) -> bool:
		return k in self.dict

	def __delitem__(self, k:str) -> None:
		del (self.dict[k])

	def reorder(self, order:typing.Iterable[str]) -> None:
		"""Reorders entries in the table. Doesn't change locations of code and names."""
		newItems = []
		for elName in order:
			newItems.append((elName, self[elName]))
		self.dict = DictT(newItems)

	def remove(self, toRemove:typing.Iterable[str]) -> None:
		"""Removes entries from the table. Doesn't removes the actual code and names"""
		for elName in toRemove:
			if elName in self:
				del (self[elName])
