from binaryninja import *
from binaryninja.plugin import PluginCommand
import re

def is_func(sym):
 if sym == 't':
   return True
 if sym == 'T':
   return True
 return False

def is_text(name):
 if name == '_stext':
   return True
 if name == '_text':
   return True
 return False

pattern = re.compile('^([0-9a-f]+) (\w) (\w+)$', re.I)
def on_select(bv):
 total = 0   # total lines readed
 found = 0   # found functions
 sadded = 0  # added symbols
 op = binaryninja.interaction.OpenFileNameField("system.map")
 result = get_form_input([op], "system.map")
 if ( result ):
   aset = set()
   state = 0
   with open(op.result) as f:
     for line in f:
       total = total + 1
       m = pattern.match(line)
       if m:
         addr = int("0x" + m.group(1), 16)
         if is_text(m.group(3)):
           state = 1
           continue
         if state !=1:
           continue
         funcs = bv.get_functions_containing(addr)
         if len(funcs):
           funcs[0].name = m.group(3)
           found = found + 1
         else:
           if addr in aset:
             continue
           # make user symbol
           bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, m.group(3)))
           sadded = sadded + 1
           aset.add(addr)
   # log
   binaryninja.log.log_info(f"total {total} found {found} functions, added {sadded} symbols")

PluginCommand.register('load system.map', 'load kernel functions names', on_select)