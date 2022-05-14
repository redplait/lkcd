#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <segment.h>
#include <nalt.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <set>
#include <map>
#include "unlzma.h"
#include "ksyms.h"

char *segm_name = "unpacked";

// remove in sdk/include/nalt.hpp #ifndef __KERNEL__ for get_input_file_path
int construct_system_map(qstring &out_res)
{
  char buf[1024], dir[1024];
  if ( !get_input_file_path(buf, _countof(buf)) )
  {
    msg("get_input_file_path failed\n");
    return 0;
  }
  qdirname(dir, _countof(dir), buf);
  char *fname = qbasename(buf);
  if ( fname == NULL )
    return 0;
  if ( _strnicmp(fname, "vmlinuz", 7) )
  {
    msg("strange name of kernel: %s\n", fname);
    return 0;
  }
  fname += 7;
  out_res = dir;
  out_res += "/System.map";
  out_res += fname;
  msg("expect %s\n", out_res.c_str());
  return 1;
}

bool try_data(ea_t &start, ea_t &end)
{
  segment_t *s = get_segm_by_name(".data");
  if ( s == NULL )
  {
    msg("cannot get .data segment\n");
    return false;
  }
  ea_t f = get_first_dref_to(s->start_ea);
  if (f == BADADDR)
  {
    msg("get_first_dref_to failed\n");
    return false;
  }
  start = s->start_ea;
  // now we need to find end of data - usually it reffered in next instruction
  func_t *func = get_func(f);
  if ( NULL == func )
    return false;
  func_item_iterator_t fii;
  for ( bool ok=fii.set(func, f); ok; ok=fii.next_code() )
  {
    ea_t ea = fii.current();
    if ( ea == BADADDR )
      return false;
    end = get_first_dref_from(ea);
    if ( end != BADADDR )
    {
      // check that this address inside .data
      if ( end > s->start_ea && end < s->end_ea )
        return true;
    }
  }
  // well, perhaps we must scan backward
  for ( bool ok=fii.set(func, f); ok; ok=fii.prev_code() )
  {
    ea_t ea = fii.current();
    if ( ea == BADADDR )
      return false;
    end = get_first_dref_from(ea);
    if ( end != BADADDR )
    {
      // check that this address inside .data
      if ( end > s->start_ea && end < s->end_ea )
        return true;
    }
  }
  return false;
}

ea_t s_curr;
int s_err = 0;

void my_err(char *x)
{
  s_err++;
  msg("error: %s\n", x);
}

long ida_fill(void *buf, unsigned long size)
{
  size_t res = get_bytes(buf, size, s_curr);
  s_curr += size;
  return res;
}

unsigned char *unpack(ea_t start, ea_t end, size_t unpacked)
{
  unsigned char *res = (unsigned char *)qalloc(unpacked);
  if ( res == NULL )
    return NULL;
  s_curr = start;
  s_err = 0;
  __decompress(NULL, end - start, ida_fill, NULL, res, 0, my_err);
  if ( s_err )
  {
    qfree(res);
    return NULL;
  }
  return res;
}

void save_unpacked(unsigned char *data, size_t unpacked)
{
  FILE *fp = qfopen("unpacked", "wb");
  if ( NULL == fp )
    return;
  qfwrite(fp, data, unpacked);
  qfclose(fp);
}

static int s_ord = 1;

void my_sym_cb(struct addr_sym *sym, char type)
{
  set_name(sym->addr, sym->name, SN_PUBLIC | SN_NOWARN);
  if ( type == 't' )
     auto_make_proc(sym->addr);
  else if ( type == 'T' )
    add_entry(++s_ord, sym->addr, sym->name, true);
  else if ( isupper(type) )
    add_entry(++s_ord, sym->addr, sym->name, false);
}

bool unlzma_run(size_t arg)
{
  // 1) get input file-name
  qstring smap_fn;
  construct_system_map(smap_fn);
  // 2) try to detect xrefs to .data section
  ea_t start = NULL, end = NULL;
  if ( !try_data(start, end) )
  {
    msg("cannot find compressed data\n");
    return false;
  }
  size_t unpacked_size = get_dword(end - 4);
  msg("start %a end %a size %d\n", start, end, unpacked_size);
  // 3) read System.map
  if ( smap_fn.empty() )
  {
    char *asked = ask_file(false, "System.map", "peek System.map for this kernel");
    if ( NULL == asked )
      return false;
    smap_fn = asked;
  } 
  ea_t text_addr = NULL; // perhaps this can be valid address?
  int err = read_ksyms(smap_fn.c_str());
  if ( err )
    msg("cannot read %s\n", smap_fn.c_str());
  else
    text_addr = get_addr("_text");
  // 4) ask address from user if can`t read it from System.map
  if ( NULL == text_addr )
  {
    if ( !ask_addr(&text_addr, "enter address of unpacked data") )
      return false;
  }
  // 5) unpack
  unsigned char *buf = unpack(start, end, unpacked_size);
  if ( NULL == buf )
    return false;
// for debug only
//  save_unpacked(buf, unpacked_size);

  // 6) add segment
  msg("base at %a\n", text_addr);
  segment_t *s = getseg(text_addr);
  if ( s != NULL )
  {
    msg("you already have segment at %a\n", text_addr);
    qfree(buf);
    return false;
  }
  segment_t ns;
  ns.start_ea = text_addr;
  ns.end_ea = text_addr + unpacked_size;
  ns.sel     = allocate_selector(text_addr >> 4);
//  set_segm_name(&ns, segm_name);
  ns.type = SEG_CODE;
//  set_segm_class(&ns, "CODE");
  ns.perm = SEGPERM_MAXVAL;
  ns.bitness = 2;
  ns.set_visible_segm(true);
  bool res = add_segm_ex(&ns, segm_name, NULL, ADDSEG_NOSREG);
  if ( !res )
  {
    qfree(buf);
    msg("add_segm_ex failed\n");
    return false;
  }
  put_bytes(text_addr, buf, unpacked_size);
  qfree(buf);
  // 7) apply System.map if presents
  if ( !err )
    enum_symbols(&my_sym_cb);
  return true;
}

/******************** CONSTANTS *******************/
char unlzma_comment[] = "Plugin for unpacking lzma-compressed linux kernel";
char unlzma_help[] =
 "before flight place System.map in the same directory where vmlinuz\n";
char unlzma_wanted_name[] = "unpack vmlinuz";
char unlzma_wanted_hotkey[] = "";

// only for elf files
plugmod_t * idaapi
unlzma_init(void)
{
  msg("unlzma: filetype %d\n", inf.filetype);
  if ( inf.filetype == f_ELF )
    return PLUGIN_OK;
  return PLUGIN_SKIP;
}

/*
 * PLUGIN description
 */
extern "C" plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,    	   // plugin flags
  unlzma_init,             // initialize function
  NULL,	                   // terminate. this pointer may be NULL.
  unlzma_run,              // invoke plugin
  unlzma_comment,          // long comment about the plugin
  unlzma_help,             // multiline help about the plugin
  unlzma_wanted_name,      // the preferred short name of the plugin
  unlzma_wanted_hotkey     // the preferred hotkey to run the plugin
};
