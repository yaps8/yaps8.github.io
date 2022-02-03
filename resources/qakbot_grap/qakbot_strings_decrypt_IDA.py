#!/usr/bin/python3
# -*- coding: utf-8 -*-

import pygrap

pattern_function="""
digraph qakbot_strings_parsing_func {
	EP [cond="nfathers>=5", getid=0_EP]
	BB [cond=true, repeat=*]
	0x3941711 [cond="opcode is 'push'", getid=1_CIPHERSIZE1]
	0x3941716 [cond="opcode is 'push'", getid=2_CIPHER]
	0x394171b [cond="opcode is 'call'"]
	0x3941720 [cond=true, repeat=*, lazyrepeat=true]
	0x3941727 [cond="opcode is 'test'"]
	0x3941729 [cond="nchildren == 2"]
	0x3941732 [cond=true]
	0x3941733 [cond="opcode is 'mov'"]
	0x3941736 [cond="opcode is 'push'"]
	0x3941737 [cond="opcode is 'mov'", getid=3_CIPHERSIZE2]
	0x394173c [cond="opcode is 'mov'"]
	0x394173e [cond="opcode is 'cmp'"]
	0x3941740 [cond="nchildren == 2"]
	0x3941742 [cond=true]
	0x3941744 [cond="opcode is 'and'", getid=4_KEYSIZE]
	0x3941747 [cond="opcode is 'mov'", getid=5_XORKEY]
	0x394174d [cond="opcode is 'xor'"]
	0x3941750 [cond="nchildren == 2"]

	EP -> BB
	BB -> 0x3941711
	0x3941711 -> 0x3941716 [childnumber=1]
	0x3941716 -> 0x394171b [childnumber=1]
	0x394171b -> 0x3941720 [childnumber=1]
	0x3941720 -> 0x3941727 [childnumber=1]
	0x3941727 -> 0x3941729 [childnumber=1]
	0x3941729 -> 0x3941732 [childnumber=2]
	0x3941732 -> 0x3941733 [childnumber=1]
	0x3941733 -> 0x3941736 [childnumber=1]
	0x3941736 -> 0x3941737 [childnumber=1]
	0x3941737 -> 0x394173c [childnumber=1]
	0x394173c -> 0x394173e [childnumber=1]
	0x394173e -> 0x3941740 [childnumber=1]
	0x3941740 -> 0x3941742 [childnumber=1]
	0x3941742 -> 0x3941744 [childnumber=1]
	0x3941744 -> 0x3941747 [childnumber=1]
	0x3941747 -> 0x394174d [childnumber=1]
	0x394174d -> 0x3941750 [childnumber=1]
}
"""

def parse_decrypt_function():
	matches = pygrap.ida_match(pattern_function, print_matches=False)
	if "qakbot_strings_parsing_func" in matches:
		for match in matches["qakbot_strings_parsing_func"]:
			func_addr = match["0_EP"][0].info.address
			size1 = pygrap.parse_first_immediate(match["1_CIPHERSIZE1"][0].info.arg1)
			cipher_addr = pygrap.parse_first_immediate(match["2_CIPHER"][0].info.arg1)
			size2 = pygrap.parse_first_immediate(match["3_CIPHERSIZE2"][0].info.arg2)
			xorkey_addr = pygrap.parse_first_address(match["5_XORKEY"][0].info.arg2)
            
			if size1 != size2 + 1:
				print("ERROR: size1 and size2 do not match")
				return
			print("Decryption function at:", hex(func_addr))
			print("XOR key at:", hex(xorkey_addr))
			print("XOR key:", idc.get_bytes(xorkey_addr, 0x40).hex())
			print("Cipher block at:", hex(cipher_addr))
			print("Cipher block size:", hex(size1))
            
			return func_addr, xorkey_addr, cipher_addr, size1
            
pattern_call="""
digraph push_call_func {
	push [cond="opcode is push", getid=PUSH]
	notpush [cond="not(opcode is push)", minrepeat=0, maxrepeat=5, lazyrepeat=true]
	call [cond="opcode is call"]
	func [cond="address == FILL_ADDRESS"]
    
	push -> notpush
	notpush -> call
	call -> func [childnumber=2]
}
"""

def decrypt_strings():
	func_addr, xorkey_addr, cipher_addr, cipher_size = parse_decrypt_function()

	pattern_call_final = pattern_call.replace("FILL_ADDRESS", hex(func_addr))
	matches = pygrap.ida_match(pattern_call_final, print_matches=False)
    
	if "push_call_func" in matches:
		for match in matches["push_call_func"]:
			push_inst = match["PUSH"][0]
			push_addr = push_inst.info.address
			offset = pygrap.parse_first_immediate(push_inst.info.arg1)
			if offset:
				dec = decrypt_string(offset, xorkey_addr, cipher_addr, cipher_size)
				print(hex(push_addr), hex(offset), dec)
				idc.set_cmt(push_addr, dec, 1)
        

def decrypt_string(offset, xorkey_addr, cipher_addr, cipher_size):
	if offset >= cipher_size:
		return
	res = ""
	while offset < cipher_size - 1:
		cipher_b = idc.get_bytes(cipher_addr+offset, 1)[0]
		key_b = idc.get_bytes(xorkey_addr + (offset&0x3F), 1)[0]
		c =  cipher_b ^ key_b
		if c == 0:
			break
		res += chr(c)
		offset += 1
	return res
    
decrypt_strings()
