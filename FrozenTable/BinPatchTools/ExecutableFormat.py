import typing
from _io import _IOBase
from pathlib import Path
import mmap
import struct


class ExecutableFormat:
	"""An abstraction allowing to parse and edit some executable formats. Wraps third-party libs."""
	module = None

	@classmethod
	def initClass(cls) -> None:
		pass

	@classmethod
	def checkInitClass(cls) -> None:
		if cls.module is None:
			cls.initClass()

	@property
	def byteness(self) -> int:
		return self.bitness // 8

	def __init__(self, source: "LocalPath") -> None:
		self.__class__.checkInitClass()

		if isinstance(source, str):
			source = Path(source)
		self.source = source

		self._fd = None
		self.map = None
		self.ptrPacker = None

	def parsePtr(self, offst:int) -> int:
		return self.ptrPacker.unpack(self.map[offst : offst + self.byteness])[0]

	def writePtr(self, offst:int, value:int) -> int:
		self.map[offst : offst + self.byteness] = self.ptrPacker.pack((value,))

	def resolvePtr(self, ptrValue:int, ptrRawVirtualAddr:int) -> int:
		"""Passing here a pointer value and pointer raw virtual addr you will get a raw virtual addr of the place the pointer points to. Relocs are processed."""
		return ptrValue

	def resolvePtrByOffset(self, ptrOffset:int) -> int:
		"""The same as resolvePtr, hut accepts an offset in file and returns the new offset"""
		ptrValueRaw = self.parsePtr(ptrOffset)
		ptrRawVirtualAddr = self.offset2Raw(ptrOffset)
		resolved = self.resolvePtr(ptrValueRaw, ptrRawVirtualAddr)
		return self.raw2Offset(resolved)

	def getPtrTypeLetter(self) -> str:
		if self.bitness == 32:
			return "I"
		elif self.bitness == 64:
			return "Q"
		elif self.bitness == 16:
			return "D"
		else:
			raise ValueError("Unsupported bitness " + str(b))

	def __enter__(self) -> typing.Union["PEFile", "ELFTools"]:
		source = self.source

		if isinstance(source, Path):
			source = source.open("r+b").__enter__()

		if isinstance(source, _IOBase):
			self._fd = source
			source = mmap.mmap(self._fd.fileno(), 0, access=mmap.ACCESS_WRITE).__enter__()

		if isinstance(source, (bytearray, mmap.mmap)):
			self.map = source

		self.__child_enter__()

		self.ptrPacker = struct.Struct(self.getPtrTypeLetter())

		return self

	def __child_enter__(self):
		pass

	def __exit__(self, *args, **kwargs) -> None:
		if self.map is not None and hasattr(self.map, "__exit__"):
			self.map.__exit__(*args, **kwargs)
			self.map = None

		if self._fd is not None:
			self._fd.__exit__(*args, **kwargs)
			self._fd = None
