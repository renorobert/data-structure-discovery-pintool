import sys
import idaapi

''' 
Highlights instructions that reads and writes to heap
based on trace from PIN tool
'''

try: trace = open("StructTrace","r").readlines()
except: sys.exit("Error opening file!")

address_read  = []
address_write = []

for line in trace:
    if '@' not in line: continue
    eip = line.split('@')[0].strip()
    if eip in address_read + address_write: continue
    if 'MREAD' in line: 
        address_read.append(eip)
    else: address_write.append(eip)

# Red
for addr in address_write:
    ea = int(addr, 16)
    idaapi.set_item_color(ea, 0xffd2f8)

# Green
for addr in address_read:
    ea = int(addr, 16)
    idaapi.set_item_color(ea, 0x00ff00)

