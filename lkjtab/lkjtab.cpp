#define USE_DANGEROUS_FUNCTIONS

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <name.hpp>

/* set comment - may be called several times with same comment */
void idaapi
rp_set_comment(ea_t ea, const char *comment, bool is_before, bool rptbl = false)
{
   if ( NULL == comment || ! *comment )
    return;
   ssize_t cmt_size = get_cmt(ea, rptbl, NULL, 0);
   if ( !cmt_size || -1 == cmt_size )
   {
      set_cmt(ea, comment, rptbl);
      return;
   }
   char *old_cmt = (char *)qalloc(cmt_size + 1);
   get_cmt(ea, rptbl, old_cmt, cmt_size);
   if ( NULL != strstr(old_cmt, comment) )
   {
     qfree(old_cmt);
     return;
   }
   if ( is_before )
   {
     int cl = strlen(comment);
     char *a = (char *)qalloc(cl + 2 + strlen(old_cmt));
     strcpy(a, comment);
     a[cl] = ',';
     strcpy(a+cl+1, old_cmt);
     set_cmt(ea, a, rptbl);
     qfree(a);
   } else
   {
     append_cmt(ea, "," , rptbl );
     append_cmt(ea, comment, rptbl );
   }
   qfree(old_cmt);
}

int idaapi
lkjtab_init(void)
{
 // we must be inside PE
 if ( inf.filetype != f_ELF )
   return PLUGIN_SKIP;
 return PLUGIN_OK;
}

// ripped from include/linux/jump_label.h
// struct jump_entry {
//  s32 code;
//  s32 target;
//  long key;	// key may be far away from the core kernel under KASLR
// };

#ifdef __EA64__
#define JSIZE  0x10
#else
#define JSIZE  0xc
#endif

void idaapi
lkjtab_run(int arg)
{
  ea_t start = get_name_ea(BADADDR, "__start___jump_table");
  if ( start == BADADDR )
  {
    msg("cannot find __start___jump_table\n");
    return;
  }
  ea_t stop = get_name_ea(BADADDR, "__stop___jump_table");
  if ( stop == BADADDR )
  {
    msg("cannot find __stop___jump_table\n");
    return;
  }
  char buf[20];
  for ( ea_t iter = start; iter < stop; iter += JSIZE )
  {
    int code = get_long(iter);
    doDwrd(iter, 4);
    int target = get_long(iter + 4);
    doDwrd(iter + 4, 4);
    ea_t code_ea = iter + code;
    ea_t target_ea = iter + 4 + target;
    qsnprintf(buf, sizeof(buf), "%a", code_ea);
    rp_set_comment(iter, buf, false);
    qsnprintf(buf, sizeof(buf), "%a", target_ea);
    rp_set_comment(iter + 4, buf, false);
    rp_set_comment(code_ea, buf, false);
  }
}

/******************** CONSTANTS *******************/
char IDC_comment[] = "Plugin for linux kernel jump-table processing";
char IDC_help[] =
 "Plugin for linux kernel jump-table processing\n";
char IDC_wanted_name[] = "lkjtab";
char IDC_wanted_hotkey[] = "Ctrl-Alt-F11";

/*
 * PLUGIN description
 */
extern "C" plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,    	// plugin flags
  lkjtab_init,          // initialize function
  NULL,	                // terminate. this pointer may be NULL.
  lkjtab_run,           // invoke plugin
  IDC_comment,          // long comment about the plugin
  IDC_help,             // multiline help about the plugin
  IDC_wanted_name,      // the preferred short name of the plugin
  IDC_wanted_hotkey     // the preferred hotkey to run the plugin
};
