def TranslatedPtr(parsed_binary, ptr_obj, _io):
	return parsed_binary.raw2Offset(parsed_binary.resolvePtr(
		ptr_obj.raw_ptr,
		parsed_binary.offset2Raw(ptr_obj._debug["raw_ptr"]["start"])
	))
