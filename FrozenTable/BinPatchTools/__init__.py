import mmap
from pathlib import Path
from importlib import import_module
import typing

formatsMapping = {
	b"MZ": "PEFile",
	b"\x7fELF": "ELFTools",
	#b"\x7fELF": "MachOLib",
}

SourceT = typing.Union[mmap.mmap, Path, str]


def getFormatCtor_(source: SourceT) -> typing.Optional[typing.Union[typing.Type["PEFile"], typing.Type["ELFTools"]]]:
	sigLen = 4

	if isinstance(source, (bytearray, mmap.mmap)):
		signature = source[0:sigLen]
	else:
		if isinstance(source, str):
			source = Path(source)
		if isinstance(source, (str, Path)):
			with source.open("rb") as f:
				signature = f.read(sigLen)
		else:
			raise ValueError("`source` is of unsupported type `" + repr(type(source)) + "`")

	for etalonSignature, backendName in formatsMapping.items():
		if signature.startswith(etalonSignature):
			pkg = import_module(".backends." + backendName, __package__)
			return getattr(pkg, backendName)


def getFormatCtor(source: SourceT) -> typing.Optional[typing.Union[typing.Type["PEFile"], typing.Type["ELFTools"]]]:
	#try:
	#	import lief
	#	from .backends.LIEF import LIEF
	#	return LIEF
	#except:
	return getFormatCtor_(source)
