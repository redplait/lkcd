// idc script to dump all ftrace_events names from linux kernel
#include <ida.idc>

static main() 
{
  auto start = LocByName("__start_ftrace_events");
  auto end = LocByName("__stop_ftrace_events");
  auto i, addr, fp;
  if ( BADADDR == start )
    return;
  if ( BADADDR == end )
    return;
  fp = fopen("events.inc", "w");
  if ( !fp )
    return;
  for ( addr = start; addr < end; addr = addr + 8 )
  {
    i = Qword(addr);
    if ( i )
    {
      auto name;
      name = Name(i);
      fprintf(fp, "\"%s\",\n", name);
      MakeUnknown(addr, 8, 0);
      MakeQword(addr);
      add_dref(addr, i, dr_O);
      MakeQword(i + 0x10);
      MakeQword(i + 0x18);
    }
  }
  fclose(fp);
}