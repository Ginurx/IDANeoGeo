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
	name_byte(0x320001, "REG_STATUS_A")
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

def set_name_with_comment(ea, name, cmm):
	idaapi.set_name(ea, name)
	idaapi.set_cmt(ea, cmm, True)


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
	file_size = li.tell()
	li.seek(0)
	
	# read p1 rom
	file_data = li.read(0x100000)
	file_remain = file_size - 0x100000
	
	idaapi.mem2base(file_data, 0, 0x100000)

	# read p2 rom
	bank2_seg_offset = 0x01000000
	bank2_seg_index = 0

	while file_remain > 0:
		bank2_seg_start = bank2_seg_offset + 0x200000
		bank2_seg_end = bank2_seg_start + 0x2FFFFF

		idaapi.add_segm(0, bank2_seg_start, bank2_seg_end, "BANK2_%d" % bank2_seg_index, "DATA")

		bytes_to_read = file_remain
		if bytes_to_read > 0x100000:
			bytes_to_read = 0x100000

		file_data = li.read(bytes_to_read)
		idaapi.mem2base(file_data, bank2_seg_start, bank2_seg_start + len(file_data))

		bank2_seg_offset += 0x01000000
		bank2_seg_index += 1
		file_remain -= bytes_to_read
	

	# http://ajworld.net/neogeodev/beginner/
	name_long(0x000000, "InitSP")
	name_long(0x000004, "InitPC")
	name_long(0x000008, "BusError")
	name_long(0x00000C, "AddressError")
	name_long(0x000010, "IllegalInstruction")
	name_long(0x000014, "DivByZero")
	name_long(0x000018, "CHK")
	name_long(0x00001C, "TRAPV")
	name_long(0x000020, "PrivilegeViolation")
	name_long(0x000024, "Trace")
	name_long(0x000028, "Line1010Emu")
	name_long(0x00002C, "Line1111Emu")
	name_array(0x000030, "Reserved0", 0xC)
	name_long(0x000003C, "UnintializedInterruptVec")
	name_array(0x000040, "Reserved1", 0x20)
	name_long(0x000060, "VirtualInterrupt")
	name_long(0x000064, "Interrupt1")
	name_long(0x000068, "Interrupt2")
	name_long(0x00006C, "Interrupt3")
	name_long(0x000070, "Interrupt4")
	name_long(0x000074, "Interrupt5")
	name_long(0x000078, "Interrupt6")
	name_long(0x00007C, "Interrupt7")
	name_dword_array(0x000080, "Traps", 0x10)
	name_array(0x0000C0, "Reserved2", 0x40)

	# Neo-Geo header
	# https://wiki.neogeodev.org/index.php?title=68k_program_header
	idc.create_strlit(0x000100, 0x000107)
	idaapi.set_name(0x000100, "Magic")
	name_byte(0x000107, "SysVersion")
	name_word(0x000108, "GameID")
	name_long(0x00010A, "ProgramSize")
	name_long(0x00010E, "BackupRAMPtr")
	name_word(0x000112, "BackupRAMSize")
	name_byte(0x000114, "EyecatchFlag")
	name_byte(0x000115, "EyecatchSpriteBank")
	name_long(0x000116, "MenuJP")
	name_long(0x00011A, "MenuUS")
	name_long(0x00011E, "MenuEU")
	name_code(0x000122, "Routine_USER", 6)
	name_code(0x000128, "Routine_PLAYER_START", 6)
	name_code(0x00012E, "Routine_DEMO_END", 6)
	name_code(0x000134, "Routine_COIN_SOUND", 6)
	name_array(0x00013A, "Unknown0", 0x48)
	name_long(0x000182, "CartridgeRecognitionCodePtr")
	name_long(0x000186, "Unknown1")
	name_long(0x00018A, "Unknown2")
	name_long(0x00018E, "MenuES")		# Spanish

	# BIOS RAM
	set_name_with_comment(0x10FD80, "BIOS_SYSTEM_MODE", 
		"0x00 : System"
		"0x80 : Game")

	set_name_with_comment(0x10FD82, 
		"BIOS_MVS_FLAG", "0 : HOME/AES\n"
		"1 : MVS")

	set_name_with_comment(0x10FDAE, "BIOS_USER_REQUEST", 
		"0 : Startup initialization\n"
		"1 : Eye-catcher\n"
		"2 : Demo Game / Game\n"
		"3 : Title Display")

	set_name_with_comment(0x10FDAF, "BIOS_USER_MODE", 
		"Current game status.\n"
		"0 : init/boot\n"
		"1 : title/demo\n"
		"2 : game")

	set_name_with_comment(0x10FEC5, "BIOS_TITLE_MODE", 
		"Newer games set this to 1 in their command 3 USER subroutine.\n"
		"It prevents the system ROM from calling command 3 twice after game over if credits are already in the system.\n")
		

	#idaapi.del_items(0x3C0000)
	# VRAM

	set_name_with_comment(0x3C0000, "REG_VRAMADDR", "sets the VRAM address for the next read/write operation.")
	set_name_with_comment(0x3C0002, "REG_VRAMRW", "the data read or to write.")
	set_name_with_comment(0x3C0004, "REG_VRAMMOD", "the signed value automatically added to the VRAM address after a write.")

	set_name_with_comment(0x3C000C, "LSPC_IRQ_ACK", "IRQ acknowledgement register.\nbit2 : Ack.VBlank | bit 1 : Ack.HBlank | bit 0 : IRQ3")

	idaapi.set_name(0xC00444, "SYSTEM_RETURN")
	idaapi.set_name(0xC0044A, "SYSTEM_IO")

	idaapi.set_name(0xD00100, "BOARD_CORRUPTED")


	#idaapi.set_cmt(0x3C0000, "Pouet.", 1)
	return 1
