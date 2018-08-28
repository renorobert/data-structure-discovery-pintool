#!/usr/bin/env python

import pygraphviz as pyg
import argparse
import collections
import re

parser = argparse.ArgumentParser(description= 'Generate memory access graph')

parser.add_argument('--filename', required=True, help='Pin trace file')
parser.add_argument('--bss', action='store_true', help='Track data/bss section', default=False)
parser.add_argument('--relink', action='store_true', help='Enable relink', default=False)
parser.add_argument('--nullwrite', action='store_true', 
			help='Enable nullwrite, this could be useful with relink', default=False)

args = vars(parser.parse_args())

pintrace  = args['filename']
bss 	  = args['bss']
relink	  = args['relink']
nullwrite = args['nullwrite']

# RegEx patterns
GLOBAL = '(data|bss)\[(0x[a-fA-F\d]+),(0x[a-fA-F\d]+)\]'
ALLOC  = '(malloc|calloc|realloc|mmap|sbrk)\[(0x[a-fA-F\d]+)\]'
RET    = 'ret\[(0x[a-fA-F\d]+)\]'
INS    = '(WRREG|WRIMM) MEM\[0x([a-fA-F\d]+)\] VAL\[(0x[a-fA-F\d]+|\d+)\]'

# Graph attributes
G = pyg.AGraph(directed=True, strict=False)

G.graph_attr['splines'] = 'line'
G.graph_attr['overlap'] = 'scale'

G.edge_attr['color'] = 'maroon'

G.node_attr['shape'] = 'record'
G.node_attr['color'] = 'cornflowerblue'

# unique id for every allocation
node_id = 0
# unique id for every link
edge_id = 0

# ordered dict for allocations
allocations = collections.OrderedDict()

# for node records
NODE_RECORD = '<z%d> 0x%x|'
NODE_HEADER = '<z%d> [%d] 0x%x|'

def c(string): 
    '''Helper function - converts hex string to int'''

    try: return int(string, 16)
    except: return string

def trace_global(trace):
    '''Create nodes for global memory from ELF'''

    for pos, ins in enumerate(trace[:2]):
	matches = re.search(GLOBAL, ins)
	section,address,size = [c(match) for match in matches.groups()]

    	create_node(address, size)

def get_addr_size(pos):
    '''Get size and address of memory allocations'''

    address = size = None
    allocsize = re.search(ALLOC, trace[pos])
    retmemory = re.search(RET, trace[pos+1])

    if allocsize and retmemory:
	func, size = [c(match) for match in allocsize.groups()]
	address, = [c(match) for match in retmemory.groups()]

    return address, size

def get_operands_from_instruction(ins):
    '''Get value of source and destination operands'''

    src_operand = des_operand = None
    operands = re.search(INS, ins)

    if operands:
	instype,des_operand,src_operand = [c(operand) for operand in operands.groups()]

    return des_operand, src_operand

def get_node_id(node_address):
    '''Given a node address, returns its node id'''

    for nid, node_info in allocations.items():
	address = node_info['address']
	if address == node_address:
	    return nid

def create_node(address, size):
    '''Create node for every new allocation'''

    global node_id
    global allocations

    new_node = collections.OrderedDict()
    new_node[node_id] = {'address': address, 'size': size}
    # add new allocations to start of ordered dictionary
    # this is to keep track of latest use of a memory address
    allocations = collections.OrderedDict(new_node.items()+allocations.items())
    
    struct = 'struct' + str(node_id)
    G.add_node(struct)
    label  = NODE_HEADER % (node_id, node_id, address)
    G.get_node(struct).attr['label'] = label
    G.get_node(struct).attr['edgecount'] = '0'
    node_id += 1

def update_node(operand, node_address):
    '''Update structure based on memory access'''

    #if operand == 0: return False

    nid = get_node_id(node_address)
    struct  = 'struct' + str(nid)
    label   = G.get_node(struct).attr['label'].split('|')
    head    = label[0]
    records = label[1:]

    if all(hex(operand) not in record for record in records):
	new_record = NODE_RECORD %(operand, operand)
	label = '|'.join(label) + new_record

	G.get_node(struct).attr['label'] = label
	return True
    return False

def edge_count(node):
    ''' Returns the number of edges for a node'''

    return int(G.get_node(node).attr['edgecount'])

def create_link(des_operand, des_node_address,
                src_operand, src_node_address):
    '''Link two nodes'''

    global edge_id
    des_nid = get_node_id(des_node_address)
    src_nid = get_node_id(src_node_address)
    des = 'struct' + str(des_nid)
    src = 'struct' + str(src_nid)
    tailport = 'z' + str(des_operand)
    headport = 'z' + str(src_operand)

    # remove already existing link, when relink is enabled
    des_tailport = G.get_node(des).attr[tailport]
    if des_tailport != None and des_tailport != '':
	tail_edge_id, head_node = des_tailport.split(':')
	G.remove_edge(des, head_node, key=tail_edge_id)

        G.get_node(des).attr['edgecount'] = str(edge_count(des)-1)
        G.get_node(head_node).attr['edgecount'] = str(edge_count(head_node)-1)
	# if NULL is written, remove link, decrement edge count and return
	if src_operand == 0: return 

    # create link for first non-NULL write or 
    # create link when old link is removed during relink
    G.add_edge(des, src, tailport=tailport, headport=headport, 
						key = str(edge_id))
    G.get_node(des).attr['edgecount'] = str(edge_count(des)+1)
    G.get_node(src).attr['edgecount'] = str(edge_count(src)+1)
    G.get_node(des).attr[tailport]  = str(edge_id) + ':' + src 
    edge_id += 1 

trace = open(pintrace).readlines()
if bss: trace_global(trace)

libc_function_names = ['malloc', 'calloc', 'realloc', 'mmap', 'sbrk']

for pos, ins in enumerate(trace):

    # trace libc function calls for address and size
    if any(function_name in ins for function_name in libc_function_names):
	address, size = get_addr_size(pos)

	# create new node for new allocations
	if address and size and address not in allocations: 
	    create_node(address, size)

    # for memory write instructions
    elif 'MREAD' not in ins:
	des_operand, src_operand = get_operands_from_instruction(ins)
	des_update_success = False

	if des_operand == None or src_operand == None: continue

	# if src value is 0, do not write unless nullwrite is enabled
	if not nullwrite and src_operand == 0: continue

	for des_node_info in allocations.values():

	    des_node_address = des_node_info['address'] 
	    des_node_size    = des_node_info['size']
	    des_node_end     = des_node_address + des_node_size

	    # update the structure to which target address belongs
	    if des_operand >= des_node_address and des_operand < des_node_end:
		des_update_success = update_node(des_operand, 
						 des_node_address)
      	        break
	# if no allocations found for des address, skip
	else: continue

	# if record already exists and relink disabled, do not create new link
	if not des_update_success and not relink: continue

	for src_node_info in allocations.values():

	    src_node_address = src_node_info['address']
	    src_node_size    = src_node_info['size']
	    src_node_end     = src_node_address + src_node_size

	    # create link if source operand in an address of allocated memory
	    if (src_operand >= src_node_address and src_operand < src_node_end):
	        update_node(src_operand, src_node_address)
		create_link(des_operand, des_node_address, 
			    src_operand, src_node_address)
		break

for nid in allocations:
    struct = 'struct' + str(nid)

    # remove nodes without links
    if G.get_node(struct).attr['edgecount'] == '0':
	G.remove_node(struct)

    # for nodes with links, sort memory
    else:
	label   = G.get_node(struct).attr['label'].split('|')
   	head    = label[0]
    	records = label[1:]

	records.sort()
	label = head + '|'.join(records)
	G.get_node(struct).attr['label'] = label
      	
G.draw('StructGraph.svg', prog = 'dot')
