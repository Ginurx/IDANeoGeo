import idaapi
import idc
import struct

def accept_file(li, n):
	#if n > 0:
	#	return 0

	li.seek(0x100)
	if li.read(7) != "NEO-GEO":
		return 0

	return "NeoGeo 68k loader"

def name_long(ea, name):
	idaapi.set_name(ea, name)
	idaapi.doDwrd(ea, 4)
	idaapi.set_offset(ea, 0, 0)

def name_array(ea, name, nitems):
	idaapi.set_name(ea, name)
	idc.make_array(ea, nitems)
	idaapi.set_offset(ea, 0, 0)

def load_file(li, neflags, format):
	if format != "NeoGeo 68k loader":
		return 0

	idaapi.set_processor_type("68000", SETPROC_ALL | SETPROC_FATAL)

	idaapi.add_segm(0, 0x000000, 0x0FFFFF, "ROM", "CODE")
	idaapi.add_segm(0, 0x100000, 0x10F2FF, "WRAM", "DATA")
	idaapi.add_segm(0, 0x10F300, 0x10FFFF, "BIOSRAM", "DATA")
	idaapi.add_segm(0, 0x200000, 0x2FFFFF, "PORT", "DATA")
	idaapi.add_segm(0, 0x300000, 0x3FFFFF, "IO", "DATA")
	idaapi.add_segm(0, 0x400000, 0x401FFF, "PALETTES", "DATA")
	idaapi.add_segm(0, 0x800000, 0xBFFFFF, "MEMCARD", "DATA")
	idaapi.add_segm(0, 0xC00000, 0xC1FFFF, "SYSROM", "DATA")
	idaapi.add_segm(0, 0xD00000, 0xD0FFFF, "BRAM", "DATA")

	li.seek(0, 2)
	size = li.tell()
	li.seek(0)
	file_data = li.read(size)
	idaapi.mem2base(file_data, 0, 0x100000)
	
	name_long(0x000000, "InitSP")
	name_long(0x000004, "InitPC")

	# http://ajworld.net/neogeodev/beginner/
	name_long(0x000008, "BusError")
	name_long(0x00000C, "AddressError")
	name_long(0x000010, "IllegalInstruction")
	name_long(0x000014, "DivByZero")
	name_long(0x000018, "CHKInstruction")
	name_long(0x00001C, "TRAPVInstruction")
	name_long(0x000020, "PrivilegeViolation")
	name_long(0x000024, "Trace")
	name_long(0x000028, "Line1010Emu")
	name_long(0x00002C, "Line1111Emu")
	name_array(0x000030, "Reserved0", 0xC)
	name_long(0x000003C, "UnintializedInterruptVec")
	name_array(0x000040, "Reserved1", 0x20)
	name_long(0x000060, "SpuriousInterrupt")
	name_long(0x000064, "InterruptLv1")
	name_long(0x000068, "InterruptLv2")
	name_long(0x00006C, "InterruptLv3")
	name_long(0x000070, "InterruptLv4")
	name_long(0x000074, "InterruptLv5")
	name_long(0x000078, "InterruptLv6")
	name_long(0x00007C, "InterruptLv7")
	name_long(0x000080, "Trap1")
	name_long(0x000084, "Trap2")
	name_long(0x000088, "Trap3")
	name_long(0x000088C, "Trap4")
	name_array(0x0000C0, "Reserved2", 0x40)

	idaapi.do_unknown(0x3C0000, 1)
	idaapi.doByte(0x3C0000, 1)
	idaapi.set_name(0x3C0000, "REG_VRAMADDR")
	#idaapi.set_cmt(0x3C0000, "Pouet.", 1)

	return 1
