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

def name_byte(ea, name):
	idaapi.set_name(ea, name)
	idaapi.create_byte(ea, 1)
	idaapi.set_offset(ea, 0, 0)

def name_word(ea, name):
	idaapi.set_name(ea, name)
	idaapi.create_word(ea, 2)
	idaapi.set_offset(ea, 0, 0)

def name_long(ea, name):
	idaapi.set_name(ea, name)
	idaapi.create_dword(ea, 4)
	idaapi.set_offset(ea, 0, 0)

def name_array(ea, name, nitems):
	idaapi.set_name(ea, name)
	idc.make_array(ea, nitems)
	idaapi.set_offset(ea, 0, 0)

def name_dword_array(ea, name, nitems):
	idaapi.set_name(ea, name)
	idaapi.create_data(ea, idaapi.dword_flag(), 4 * nitems, idaapi.BADNODE)
	idaapi.set_offset(ea, 0, 0)

def name_code(ea, name, size):
	idaapi.set_name(ea, name)
	idaapi.create_data(ea, idaapi.code_flag(), size, idaapi.BADNODE)

def map_io_registers():
	# https://wiki.neogeodev.org/index.php?title=Memory_mapped_registers
	name_byte(0x300000, "REG_P1CNT")
	name_byte(0x300001, "REG_DIPSW")
	name_byte(0x300081, "REG_SYSTYPE")
	name_byte(0x320000, "REG_SOUND")
	name_byte(0x320000, "REG_STATUS_A")
	name_byte(0x340000, "REG_P2CNT")
	name_byte(0x380000, "REG_STATUS_B")
	name_byte(0x380001, "REG_POUTPUT")
	name_byte(0x380011, "REG_CRDBANK")
	name_byte(0x380021, "REG_SLOT")
	name_byte(0x380031, "REG_LEDLATCHES")
	name_byte(0x380041, "REG_LEDDATA")
	name_byte(0x380051, "REG_RTCCTRL")
	name_byte(0x380061, "REG_RESETCC1")
	name_byte(0x380063, "REG_RESETCC2")
	name_byte(0x380065, "REG_RESETCL1")
	name_byte(0x380067, "REG_RESETCL2")
	name_byte(0x3800E1, "REG_SETCC1")
	name_byte(0x3800E3, "REG_SETCC2")
	name_byte(0x3800E5, "REG_SETCL1")
	name_byte(0x3800E7, "REG_SETCL2")


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

	map_io_registers()

	li.seek(0, 2)
	size = li.tell()
	li.seek(0)
	file_data = li.read(size)
	idaapi.mem2base(file_data, 0, 0x100000)
	
	# http://ajworld.net/neogeodev/beginner/
	name_long(0x000000, "InitSP")
	name_long(0x000004, "InitPC")
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
	name_dword_array(0x000080, "Traps", 0x10)
	name_array(0x0000C0, "Reserved2", 0x40)

	# Neo-Geo header
	# https://wiki.neogeodev.org/index.php?title=68k_program_header
	idc.create_strlit(0x000100, 0x000107)
	idaapi.set_name(0x000100, "Magic")
	name_byte(0x000107, "SysVersion")
	name_word(0x000108, "GameID")
	name_long(0x00010A, "ProgramSize")
	name_long(0x00010E, "BakupRamPtr")
	name_word(0x000112, "GameSaveSize")
	name_byte(0x000114, "EyecatchFlag")
	name_byte(0x000115, "EyecatchSpriteBank")
	name_long(0x000116, "DipsJP")
	name_long(0x00011A, "DipsUS")
	name_long(0x00011E, "DipsEU")
	name_code(0x000122, "Routine_USER", 6)
	name_code(0x000128, "Routine_PLAYER_START", 6)
	name_code(0x00012E, "Routine_DEMO_END", 6)
	name_code(0x000134, "Routine_COIN_SOUND", 6)
	name_array(0x00013A, "Unknown0", 0x48)
	name_long(0x000182, "SecurityCodePtr")
	name_long(0x000186, "Unknown1")
	name_long(0x00018A, "Unknown2")
	name_long(0x00018E, "DipsES")		# Spanish

	idaapi.del_items(0x3C0000)
	idaapi.create_byte(0x3C0000, 1)
	idaapi.set_name(0x3C0000, "REG_VRAMADDR")
	#idaapi.set_cmt(0x3C0000, "Pouet.", 1)

	return 1
