#include "ldso.h"

int ldso::process()
{
  read_syms();
  // find string --library-path
  ptrdiff_t coff = find_cstr("--library-path");
  if ( coff == NULL )
  {
    printf("cannot find string --library-path\n");
    return 0;
  }
  printf("string at %p\n", coff);
  // now place where it used
  ptrdiff_t clea = find_lea(coff);
  if ( !clea )
  {
    printf("cannot find xref to --library-path\n");
    return 0;
  }
  printf("clea %p\n", clea);
  // then assigning to library_path
  if ( !find_lpath(clea) )
  {
    printf("cannot find library_path\n");
    return 0;
  }
  // where library_path is used
  ptrdiff_t maddr = find_mov(library_path);
  if ( !maddr )
  {
    printf("cannot find xref to library_path\n");
    return 0;
  }
  // next call must be _dl_init_paths
  ptrdiff_t _dl_init_paths = next_call(maddr);
  if ( !_dl_init_paths )
  {
    printf("cannot find _dl_init_paths\n");
    return 0;
  }
  printf("_dl_init_paths %p\n", _dl_init_paths);
  // finally try to get rtld_search_dirs from _dl_init_paths
  if ( !find_rtld_search_dirs(_dl_init_paths) )
  {
    printf("cannot find rtld_search_dirs\n");
    return 0;
  }
  return (rtld_search_dirs != NULL);
}

void ldso::dump() const
{
  if ( library_path )
    printf("library_path: %p\n", library_path);
  if ( rtld_search_dirs )
    printf("rtld_search_dirs: %p\n", rtld_search_dirs);
}

ptrdiff_t ldso::next_call(ptrdiff_t off)
{
  if ( !setup(off) )
    return 0;
  for ( int i = 0; i < 10; i++ )
  {
    if ( !ud_disassemble(&ud_obj) )
      return 0;
#ifdef _DEBUG
    printf("%p %s (I: %d size %d, II: %d size %d)\n", (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
      ud_obj.operand[0].type, ud_obj.operand[0].size,
      ud_obj.operand[1].type, ud_obj.operand[1].size
    );
#endif /* _DEBUG */
    if ( is_end() )
      break;
    if ( is_call_jimm() )
       return get_addr(0);
  }
  return NULL;
}

int ldso::find_rtld_search_dirs(ptrdiff_t off)
{
  if ( !setup(off) )
    return 0;
  // state 1 - edi/rdi inited
  //       2 - call happened
  int state = 0;
  for ( int i = 0; i < 20; i++ )
  {
    if ( !ud_disassemble(&ud_obj) )
      return 0;
#ifdef _DEBUG
    printf("state %d %p %s (I: %d size %d, II: %d size %d)\n", state, (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
      ud_obj.operand[0].type, ud_obj.operand[0].size,
      ud_obj.operand[1].type, ud_obj.operand[1].size
    );
#endif /* _DEBUG */
    if ( is_end() )
      break;
    if ( !state )
    {
      if ( (ud_obj.mnemonic == UD_Imov) &&
           (ud_obj.operand[0].type == UD_OP_REG) &&
           (ud_obj.operand[0].base == UD_R_EDI)
         )
        state = 1;
      continue;
    }
    if ( 1 == state )
    {
      if ( is_call_jimm() )
        state = 2;
      continue;
    }
    if ( 2 == state )
    {
      if ( is_memw(UD_Imov) )
      {
        ptrdiff_t daddr = get_addr(0);
        if ( in_section(daddr) )
        {
          rtld_search_dirs = daddr;
          return 1;
        }
      }
    }
  }
  return 0;
}

int ldso::find_lpath(ptrdiff_t off)
{
  if ( !setup(off) )
    return 0;
  for ( int i = 0; i < 20; i++ )
  {
    if ( !ud_disassemble(&ud_obj) )
      return 0;
#ifdef _DEBUG
    printf("%p %s (I: %d size %d, II: %d size %d)\n", (void *)ud_insn_off(&ud_obj), ud_insn_asm(&ud_obj),
      ud_obj.operand[0].type, ud_obj.operand[0].size,
      ud_obj.operand[1].type, ud_obj.operand[1].size
    );
#endif /* _DEBUG */
    if ( is_end() )
      break;
    if ( is_memw(UD_Imov) )
    {
      ptrdiff_t daddr = get_addr(0);
      if ( in_section(daddr) )
      {
        library_path = daddr;
        break;
      }  
    }
  }
  return (library_path != NULL);
}