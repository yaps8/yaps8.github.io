#!/usr/bin/python3
# -*- coding: utf-8 -*-

import pygrap
import pefile
import sys
import os

def print_usage():
    print("You need one argument: the (qakbot) binary to analyze")

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

def parse_decrypt_function(pe, pe_baseaddr, pe_cfg):
    matches = pygrap.match_graph(pattern_function, pe_cfg)
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
            print("XOR key:", pe.get_data(xorkey_addr - pe_baseaddr, 0x40).hex())
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

def decrypt_strings(pe, pe_baseaddr, pe_cfg):
    r = parse_decrypt_function(pe, pe_baseaddr, pe_cfg)
    if r is None:
        print("ERROR: unable to find the decryption function")
        sys.exit(1)
    func_addr, xorkey_addr, cipher_addr, cipher_size = r

    pattern_call_final = pattern_call.replace("FILL_ADDRESS", hex(func_addr))
    matches = pygrap.match_graph(pattern_call_final, pe_cfg)
    
    print("\nStrings:")
    if "push_call_func" in matches:
        for match in matches["push_call_func"]:
            push_inst = match["PUSH"][0]
            push_addr = push_inst.info.address
            offset = pygrap.parse_first_immediate(push_inst.info.arg1)
            if offset:
                dec = decrypt_string(pe, pe_baseaddr, offset, xorkey_addr, cipher_addr, cipher_size)
                print(hex(push_addr), hex(offset), dec)
        

def decrypt_string(pe, pe_baseaddr, offset, xorkey_addr, cipher_addr, cipher_size):
    if offset >= cipher_size:
        return
    res = ""
    while offset < cipher_size - 1:
        cipher_b = pe.get_data(cipher_addr + offset - pe_baseaddr, 1)[0]
        key_b = pe.get_data(xorkey_addr + (offset&0x3F) - pe_baseaddr, 1)[0]
        c =  cipher_b ^ key_b
        if c == 0:
            break
        res += chr(c)
        offset += 1
    return res

def main():
    if len(sys.argv) <= 1:
        print_usage()
        sys.exit(1)
    else:
        bin_path = sys.argv[1]
        dot_path = sys.argv[1] + ".grapcfg"

    if bin_path[-8:] == ".grapcfg":
        print("ERROR: The argument should be binary file, not a .grapfile file")
        sys.exit(1)

    # use_existing specifies wether an existing dot file should be used unchanged or overwritten
    pygrap.disassemble_file(bin_path=bin_path, dot_path=dot_path, use_existing=True)

    if not os.path.isfile(bin_path) or not os.path.isfile(dot_path):
        print("ERROR: binary or dot file doesn't exist, exiting.")
        sys.exit(1)

    print("---")
    print("Sample:", bin_path)

    try:
        data = open(bin_path, "rb").read()
        pe = pefile.PE(data=data)
        pe_baseaddr = pe.OPTIONAL_HEADER.ImageBase
    except:
        print("ERROR: pefile failed")
        sys.exit(1)
    
    pe_cfg = pygrap.getGraphFromPath(dot_path)
    decrypt_strings(pe, pe_baseaddr, pe_cfg)



main()
