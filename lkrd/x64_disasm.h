#pragma once
#include <map>
#define __UD_STANDALONE__
#include "libudis86/types.h"
#include "libudis86/extern.h"
#include "libudis86/itab.h"
#include "types.h"
#include "cf_graph.h"

template <typename V>
class used_regs
{
  public:
    void add(ud_type reg, V value)
    {
      try
      {
        m_regs[reg] = value;
      } catch(std::bad_alloc)
      { }
    }
    int add_off(ud_type reg_dst, ud_type reg_src, V value)
    {
      auto iter = m_regs.find(reg_src);
      if ( iter == m_regs.end() )
        return 0;
      if ( reg_dst == reg_src )
        add(reg_dst, value);
      else
        add(reg_dst, iter->second + value);
      return 1;
    }
    V add_zero(ud_type reg_dst, ud_type reg_src, V value)
    {
      auto iter = m_regs.find(reg_src);
      if ( iter == m_regs.end() )
      {
        add(reg_dst, value);
        return value;
      }
      if ( reg_dst == reg_src )
        add(reg_dst, value);
      else
        add(reg_dst, iter->second + value);
      return iter->second + value;
    }
    void erase(ud_type reg)
    {
      auto iter = m_regs.find(reg);
      if ( iter != m_regs.end() )
        m_regs.erase(iter);
    }
    int asgn(ud_type reg, V &out_value)
    {
      auto iter = m_regs.find(reg);
      if ( iter != m_regs.end() )
      {
        out_value = iter->second;
        return 1;
      }
      return 0;
    }
    int mov(ud_type src, ud_type dst)
    {
      auto iter = m_regs.find(src);
      if ( iter == m_regs.end() )
        return 0;
      add(dst, iter->second);
      return 1;
    }
    int exists(ud_type reg) const
    {
      auto iter = m_regs.find(reg);
      if ( iter == m_regs.end() )
        return 0;
      return 1;
    }
    inline void clear()
    {
      m_regs.clear();
    }
    inline int empty() const
    {
      return m_regs.empty();
    }
    inline size_t size() const
    {
      return m_regs.size();
    }
    inline int asgn_first(V &out_value) const
    {
      if ( m_regs.empty() )
        return 0;
      out_value = m_regs.begin()->second;
      return 1;
    }
    // graph machinery
    bool operator<(const used_regs &outer) const
    {
      return ( m_regs.size() < outer.m_regs.size() );
    }
  protected:
    std::map<ud_type, V> m_regs;
};

class x64_disasm
{
  public:
    x64_disasm(a64 text_base, size_t text_size, const char *text, a64 data_base, size_t data_size)
     : m_text_base(text_base),
       m_text_size(text_size),
       m_data_base(data_base),
       m_data_size(data_size),
       m_text(text)
    {
      m_bss_base = 0;
      m_bss_size = 0;
      ud_init(&ud_obj);
      ud_set_mode(&ud_obj, 64);
#ifdef _DEBUG
      ud_set_syntax(&ud_obj, UD_SYN_INTEL);
#endif /* _DEBUG */
    }
    void set_indirect_thunk(a64 addr, ud_type reg)
    {
      m_indirect_thunks[addr] = reg;
    }
    void set_bss(a64 addr, size_t size)
    {
      m_bss_base = addr;
      m_bss_size = size;
    }
    ud_type check_thunk(a64 addr) const
    {
      auto c = m_indirect_thunks.find(addr);
      if ( c == m_indirect_thunks.end() )
        return UD_NONE;
      return c->second;
    }
    int process(a64 addr, std::map<a64, a64> &, std::set<a64> &out_res);
  protected:
    int set(a64 addr)
    {
      if ( addr < m_text_base || addr >= (m_text_base + m_text_size) )
        return 0;
      size_t avail = m_text_base + m_text_size - addr;
      const char *buf = m_text + (addr - m_text_base);
      ud_set_input_buffer(&ud_obj, (uint8_t *)buf, avail);
      ud_set_pc(&ud_obj, (uint64_t)addr);
      return 1;
    }
    inline int in_data(a64 addr)
    {
      if ( addr >= m_bss_base && addr < (m_bss_base + m_bss_size) )
        return 1;
      return ( addr >= m_data_base && addr < (m_data_base + m_data_size) );
    }
    int is_jmp() const;
    int is_jxx_jimm() const;
    int reg32to64(ud_type from, ud_type &res) const;
    ud_type expand_reg(int idx) const;
    // will be filled with sequence of set_indirect_thunk methods
    std::map<a64, ud_type> m_indirect_thunks;

    ud_t ud_obj;
    a64 m_text_base;
    size_t m_text_size;
    a64 m_data_base;
    size_t m_data_size;
    const char *m_text;
    a64 m_bss_base;
    size_t m_bss_size;
};