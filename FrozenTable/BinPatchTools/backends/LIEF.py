from ..ExecutableFormat import ExecutableFormat

import lief
from ELFMachine import ELFMachine
from ELFRelocs.libs.LIEF import LIEFRelocator


class LIEF(ExecutableFormat):
	def __child_enter__(self):
		self.parsed = lief.parse(str(self.source))
		self.bitness = ( 64 if self.parsed.abstract.header.is_64 else (32 if self.parsed.abstract.header.is_32 else None) )
		print(isinstance(self.parsed.concrete, lief.ELF.Binary))
		if isinstance(self.parsed.concrete, lief.ELF.Binary):
			self.relocator = LIEFRelocator(self.parsed)

	def findVA(self, name):
		"""Gets a symbol addr from ELF export table"""
		if isinstance(self.parsed.concrete, lief.PE.Binary):
			return [el for el in self.parsed.abstract.exported_functions if el.name == name][0].value + self.parsed.concrete.optional_header.imagebase#FUCK, value is RVA in the case of PE
		else:
			return self.parsed.concrete.get_symbol(name).value #FUCK it doesn't get any results for PE

	def raw2Offset(self, raw):
		# FUCK, inconsistent API, for PE it is va_to_offset, for ELF it is virtual_address_to_offset

		func = None
		if hasattr(self.parsed.concrete, "virtual_address_to_offset"):
			func = self.parsed.concrete.virtual_address_to_offset
		elif hasattr(self.parsed.concrete, "va_to_offset"):
			func = self.parsed.concrete.va_to_offset
		else:
			raise NotImplementedError()

		return func(raw)

	def offset2Raw(self, offs):
		# FUCK, inconsistent API, for PE it is section_from_offset, for ELF it is segment_from_offset

		if hasattr(self.parsed.concrete, "segment_from_offset"):
			seg = self.parsed.segment_from_offset(offs)
		elif hasattr(self.parsed.concrete, "section_from_offset"):
			seg = self.parsed.concrete.section_from_offset(offs)

		if hasattr(seg, "file_offset"):
			baseOfs = seg.file_offset
		elif hasattr(seg, "offset"):
			baseOfs = seg.offset

		res = seg.virtual_address + offs - baseOfs

		if isinstance(self.parsed.concrete, lief.PE.Binary):
			res += self.parsed.concrete.optional_header.imagebase # FUCK, virtual_address is RVA in the case of PE

		return res
	
	def resolvePtr(self, ptrValue, ptrRawVirtualAddr):
		if self.relocator is not None:
			return self.relocator.computeRelocatedPtr(ptrRawVirtualAddr, ptrValue)[1]
		else:
			return ptrValue

