from binaryninja import *
from binaryninja.plugin import PluginCommand
import re

pattern = re.compile('^([0-9a-f]+) (\w) (\w+)$', re.I)
def on_select(bv):
 total = 0
 found = 0
 op = binaryninja.interaction.OpenFileNameField("system.map")
 result = get_form_input([op], "system.map")
 if ( result ):
   with open(op.result) as f:
     for line in f:
       total = total + 1
       m = pattern.match(line)
       if m:
         addr = int("0x" + m.group(1), 16)
         funcs = bv.get_functions_containing(addr)
         if len(funcs):
           funcs[0].name = m.group(3)
           found = found + 1
   # log
   binaryninja.log.log_info(f"total {total} found {found}")

PluginCommand.register('load system.map', 'load kernel functions names', on_select)