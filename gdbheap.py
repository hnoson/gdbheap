import gdb
import sys
import string

class Heap(gdb.Command):
    '''Display heap chunks
Usage:
    heap
    heap index(dec)
    heap address(hex)'''
    def __init__(self):
        gdb.Command.__init__(self,"heap",gdb.COMMAND_DATA)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        try:
            chunks, heap_base = get_chunk_info()
        except TypeError:
            print('No symbol table is loaded.')
            return
        if heap_base == 0:
            print('heap area is not allocated.')
            return
        print('(Legend: %s, %s)\n' % (coloring('in use','blue'),coloring('not in use', 'green')))
        print('heap base: %#x' % heap_base)

        arch, bits = peda.getarch()
        word = bits // 8

        args = args.split(' ')
        start = 0
        if len(args[0]) > 0:
            if all([x.isdigit() for x in args[0]]):
                start = int(args[0])
            elif args[0][:2] == '0x' and all([x in string.hexdigits for x in args[0][2:]]):
                addr = int(args[0],16)
                start = -1
                for index, c_addr in enumerate(sorted(chunks.keys())):
                    if addr == c_addr or addr == c_addr + 2 * word:
                        start = index
                if start < 0:
                    print('No chunk is allocated at %#x' % addr)
                    return

        for index, addr in enumerate(sorted(chunks.keys())):
            chunk = chunks[addr]
            if index >= start:
                if index > start and (index - start) % 4 == 0:
                    sys.stdout.write('--More--(%d/%d)' % (index,len(chunks)))
                    c = input()
                    if c == 'q':
                        break
                if chunk['in_use']:
                    color = 'blue'
                else:
                    color = 'green'
                print('\nHEAP[%d] is at %s' % (index,coloring(hex(addr),color)))
                print('prev_size: %s' % chunk['prev_size'])
                print('size\t : %s' % coloring(chunk['size'],color))
                if chunk['in_use']:
                    fd = str(chunk['fd'])
                else:
                    fd_chain = examine_forward_chain(chunk['fd'])
                    if len(fd_chain) > 6:
                        fd_chain = fd_chain[:6] + '...'
                    fd = ' --> '.join(map(str,fd_chain))
                if chunk['in_use'] or chunk['size'] <= 0x12 * word:
                    bk = str(chunk['bk'])
                else:
                    bk_chain = examine_backward_chain(chunk['bk'])
                    if len(bk_chain) > 6:
                        bk_chain = bk_chain[:6] + '...'
                    bk = ' --> '.join(map(str,bk_chain))
                print('fd\t : %s' % fd)
                print('bk\t : %s' % bk)

def get_chunk_info():
    try:
        top = gdb.parse_and_eval('main_arena.top')
        heap_base = gdb.parse_and_eval('mp_.sbrk_base')
        fastbins = gdb.parse_and_eval('main_arena.fastbinsY')
    except gdb.error:
        return None
    arch, bits = peda.getarch()
    word = bits // 8
    addr = cast_pointer(heap_base,'long')
    chunks = {}
    while addr < top:
        chunks[val_to_int(addr)] = {
                'prev_size': addr.referenced_value(),
                'size': (addr + 1).referenced_value(),
                'fd': (addr + 2).referenced_value(),
                'bk': (addr + 3).referenced_value(),
                'in_use': True
                }
        size = chunks[val_to_int(addr)]['size']
        prev_size = chunks[val_to_int(addr)]['prev_size']
        if not size & 1:
            chunks[val_to_int(addr - prev_size / word)]['in_use'] = False
        addr += (size & ~7) / word
    for i in range(10):
        addr = fastbins[i]
        while addr > 0:
            chunks[val_to_int(addr)]['in_use'] = False
            addr = cast_pointer(addr,'long')
            addr = (addr + 2).referenced_value()
    return chunks,val_to_int(heap_base)

def examine_free_list(start,offset):
    arch, bits = peda.getarch()
    chain = [start]
    addr = start
    while peda.is_address(val_to_int(addr)):
        addr = cast_pointer(addr,'long')
        addr = (addr + offset).referenced_value()
        if addr == start: break
        chain.append(addr)
    return chain

def examine_forward_chain(fd):
    return examine_free_list(fd,2)

def examine_backward_chain(bk):
    return examine_free_list(bk,3)

def cast(val,_type):
    return val.cast(gdb.lookup_type(_type))

def cast_pointer(val,_type):
    return val.cast(gdb.lookup_type(_type).pointer())

def val_to_int(val):
    arch, bits = peda.getarch()
    return (int(cast(val,'long')) + (1<<bits)) % (1<<bits)

def coloring(val,color):
    dic = {
            'black'  : '\x1b[30m',
            'red'    : '\x1b[31m',
            'green'  : '\x1b[32m',
            'yellow' : '\x1b[33m',
            'blue'   : '\x1b[34m',
            'magenta': '\x1b[35m',
            'cyan'   : '\x1b[36m',
            'white'  : '\x1b[37m',
            'reset'  : '\x1b[39m'
            }
    return dic[color] + str(val) + dic['reset']

Heap()
