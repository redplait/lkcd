from binaryninja import *
import ctypes
from binaryninja.plugin import PluginCommand

g_linux_sync = [
 [ 'down', 'up' ],
 [ 'mutex_lock', 'mutex_unlock' ],
 [ 'down_write', 'up_write' ],
 [ 'down_read', 'up_read' ],
 [ '_raw_spin_lock_irqsave', '_raw_spin_unlock_irqrestore' ],
 [ '_raw_write_lock_bh', '_raw_write_unlock_bh' ],
 [ '_raw_spin_lock_bh', '_raw_spin_unlock_bh' ],
 [ 'lock_vector_lock', 'unlock_vector_lock' ],
 [ 'cpus_read_lock', 'cpus_read_unlock' ],
 [ 'cpus_write_lock', 'cpus_write_unlock' ],
 [ '__srcu_read_lock', '__srcu_read_unlock' ],
 [ 'trace_event_read_lock', 'trace_event_read_unlock' ],
 [ 'kretprobe_table_lock', 'kretprobe_hash_unlock' ],
]

def is_const_ptr(op):
 return op.operation in [LowLevelILOperation.LLIL_CONST_PTR]

def get_jimm(op):
 return ctypes.c_uint64(op.value.value).value

def process_pair(bv, up, down):
 up_addrs = bv.get_symbols_by_name(up)
 if not up_addrs:
   binaryninja.log.log_info(f"cannot find address of up function {up}")
   return 0
 up_addr = up_addrs[0].address
 down_addrs = bv.get_symbols_by_name(down)
 if not down_addrs:
   binaryninja.log.log_info(f"cannot find address of down function {down}")
   return 0
 down_addr = down_addrs[0].address
 # ok, get x-refs to up
 refs = bv.get_code_refs(up_addr)
 # log
 lrefs = len(refs)
 binaryninja.log.log_info(f"{up} has {lrefs} refs")
 blocks = 0
 for ref in refs:
   addr = ref.address
   func = bv.get_functions_containing(addr)[0]
   if not func:
     continue
   bl = func.get_basic_block_at(addr)
   if not bl:
     continue
   # ok, we have function and block
   addr = addr + bv.get_instruction_length(addr)
   pr_branches = {}
   branches = {}
   state = 1
   while addr <= bl.end:
     expr = func.get_llil_at(addr)
     if not expr:
       break
     # ret
     if expr.operation.name == "LLIL_RET" and state:
       binaryninja.log.log_info("found not-paired at 0x%x" % addr)
       break
     # check for unlock call
     if expr.operation.name in {"LLIL_CALL", "LLIL_TAILCALL"} and is_const_ptr(expr.dest) and get_jimm(expr.dest) == down_addr:
       state = 0
       break
     # collect outcoming branches
     if expr.operation.name in {"LLIL_JUMP", "LLIL_JUMP_TO"} and is_const_ptr(expr.dest):
       jaddr = get_jimm(expr.dest)
       if jaddr in pr_branches:
         if pr_branches[jaddr]:
           binaryninja.log.log_info("found not-paired block at 0x%x" % addr)
       elif not jaddr in branches:
         branches[jaddr] = state
     # for next iteration
     addr = addr + bv.get_instruction_length(addr)
   blocks = blocks + 1

   # add this branch as processed
   pr_branches[bl.start] = state
   # now process branches
   while branches:
    curr_branches = branches.keys()
    branches.clear()
    for addr in curr_branches:
      state = 1
      if addr in pr_branches:
        continue
      bl = func.get_basic_block_at(addr)
      while addr <= bl.end:
        expr = func.get_llil_at(addr)
        if not expr:
          break
        # check for ret
        if expr.operation.name == "LLIL_RET":
          binaryninja.log.log_info("found not-paired at 0x%x" % addr)
          break
        # check for unlock call
        if expr.operation.name in {"LLIL_CALL", "LLIL_TAILCALL"} and is_const_ptr(expr.dest) and get_jimm(expr.dest) == down_addr:
          state = 0
          break
        # collect outcoming branches
        if expr.operation.name in {"LLIL_JUMP", "LLIL_JUMP_TO"} and is_const_ptr(expr.dest):
          jaddr = get_jimm(expr.dest)
          if jaddr in pr_branches:
            if pr_branches[jaddr]:
              binaryninja.log.log_info("found not-paired block at 0x%x" % addr)
          elif not jaddr in branches:
           branches[jaddr] = state
        # for next iteration
        addr = addr + bv.get_instruction_length(addr)
      # add this branch to processed
      pr_branches[bl.start] = state
      # inc processed blocks
      blocks = blocks + 1

 # log processed blocks
 binaryninja.log.log_info(f"processed {blocks} blocks")
 return lrefs

def on_select(bv):
 pairs = 0
 found = 0
 for pair in g_linux_sync:
   pairs = pairs + 1
   found = found + process_pair(bv, pair[0], pair[1])
 # log
 binaryninja.log.log_info(f"total {pairs} found {found}")

def my_dump_llil(bv, addr):
 funcs = bv.get_functions_containing(addr)
 if not func:
   return
 func = funcs[0]
 bl = func.get_basic_block_at(addr)
 if not bl:
   return
 while addr <= bl.end:
   binaryninja.log.log_info("%x %s" % (addr, expr.operation.name) )
   addr = addr + bv.get_instruction_length(addr)

PluginCommand.register('chsync', 'check pairing of sync functions', on_select)
# dump llil
PluginCommand.register_for_address('dump_llil', 'dump LLIL', my_dump_llil)