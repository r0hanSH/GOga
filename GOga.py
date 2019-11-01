import idaapi
import idc
import idautils
import re


class Hack:

	def __init__(self):
		# Endianness and arch
		cpu_info = idaapi.get_inf_structure()

		# big-endian check
		try:
		    be = cpu_info.is_be()   # IDA7 beta 3 (170724) onwards
		except:
		    be = cpu_info.mf  # older versions

		if be:
			self.header = "ff ff ff fb 00 00" # Big-endian
		else:
			self.header = "fb ff ff ff 00 00" # Little-endian

		# arch, only check for 64bit bcoz every 64bit will return True for is_32bit()
		# warning: only considering whether binary is 64bit or 32bit, no check for 16
		if cpu_info.is_64bit():
			self.addr_size = 8
			self.arch_word = Qword	
		else:
			self.addr_size = 4
			self.arch_word = Dword

	def go_version(self):
		sc = idautils.Strings()
		tmp = ""
		version = "go1."
		idx = -1
		for s in sc:
			idx = str(s).find("go1.")
			if (idx+1):
				tmp = str(s)
				break

		take = 5 if len(tmp) > 5 else len(tmp)-4
		for i in range(take): # 5 bcoz, max version could be go1.XX.XX (enumerate XX.XX)
			if tmp[idx+4+i] in ".0123456789":
				version += tmp[idx+4+i]
			else:
				break
		return version


	# we could search for .gopclntab segment (SHIFT+F7), but this segment only present in ELF binaries, so general approach is to find the header "fbffffff0000" of .gopclntab
	def find_gopclntab(self):
		found = False
		try:
			ea = idaapi.get_segm_by_name(".gopclntab").startEA
			found = True
		except:
			ea = MinEA()
			ea = FindBinary(ea, SEARCH_DOWN, self.header)
			if ea!=0xffffffffffffffff:
				found = True
		return (found, ea)

	def func_recovery(self, gopclntab):
		seg_size = self.arch_word(gopclntab + 8)
		func_i = gopclntab + 8 + self.addr_size # first func
		read_end = func_i + (seg_size*self.addr_size*2)
		
		"""Pseudo struct inside .gopclntab
		struct funcInfo{
			(Qword or Dword) funcAddr;
			(Qword or Dword) offset;
		}
		"""
		cnt = 0
		while gopclntab < read_end:
			offset = self.arch_word(func_i + self.addr_size)
			func_i += 2*self.addr_size # say self.addr_size = 8, 16 = 8(bypass present func_i) + 8(bypass present func_i's offset), see struct given above
			func_ptr = gopclntab + offset
			funcAddr = self.arch_word(func_ptr)
			nameOffset = Dword(func_ptr + self.addr_size) # note Dword
			func_name = GetString(gopclntab + nameOffset)
			if func_name == None:
				return str(cnt)
			cnt += 1
			func_name = re.sub("[^a-z0-9\/\.]", "_", func_name, flags=re.IGNORECASE)
			idc.MakeNameEx(funcAddr, func_name, idc.SN_NOWARN)

		return str(cnt)


if __name__ == '__main__':
	hack = Hack()

	version = hack.go_version()
	found, gopclntab = hack.find_gopclntab()


	if version != "go1.":
		print "Found[+]  GO version : " + version
	else:
		print "Found[-]  Unable to find GO version"

	if found:
		print "Found[+]  .gopclntab : " + hex(gopclntab)
	else:
		print "Found[-]  Unable to find .gopclntab segment"
		print "Exiting... unable to find any metadata"
		exit(1)

	cnt = hack.func_recovery(gopclntab)
	print "REnamed[+]  " + cnt + " functions"