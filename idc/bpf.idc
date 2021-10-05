// idc script to dump all bpf tracepoints from linux kernel
#include <ida.idc>

static main() 
{
  auto start = LocByName("__start__bpf_raw_tp");
  auto end = LocByName("__stop__bpf_raw_tp");
  auto i, addr, fp;
  if ( BADADDR == start )
  {
    msg("cannot find __start__bpf_raw_tp\n");
    return;
  }
  if ( BADADDR == end )
  {
    msg("cannot find __stop__bpf_raw_tp\n");
    return;
  }
  fp = fopen("bpf.inc", "w");
  if ( !fp )
    return;
  for ( addr = start; addr < end; addr = addr + 0x20 )
  {
    i = Qword(addr);
    if ( i )
    {
      auto name;
      MakeQword(addr);
      add_dref(addr, i, dr_O);
      name = Name(i);
      fprintf(fp, "\"%s\",\n", name);
    }
    i = Qword(addr + 8);
    if ( i )
    {
      MakeQword(addr + 8);
      add_dref(addr + 8, i, dr_O);
    }
  }
  fclose(fp);
}