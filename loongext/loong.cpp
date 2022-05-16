#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

// test 47 80 FF 03
// must be pinsrh_0

static const char node_name[] = "$ sample loongson processor extender parameters";

// SINT (8, 6);
void lop_plusa(unsigned long l, op_t &x)
{
  x.type = o_displ;
  x.offb = (l >> 6) & 0xff;
}

// REG (5, 21, GP);
void lop_b(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 21) & 0x1f;
}

// SINT (8, 3);
void lop_plusb(unsigned long l, op_t &x)
{
  x.type = o_displ;
  x.offb = (l >> 3) & 0xff;
}

// INT_ADJ(9, 6
void lop_plusc(unsigned long l, op_t &x)
{
  x.type = o_displ;
  x.offb = (l >> 6) & 0x1ff;
}

// REG (5, 11, GP);
void lop_d(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 11) & 0x1f;
}

// REG (5, 21, GP);
void lop_s(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 21) & 0x1f;
}

// REG (5, 16, GP);
void lop_t(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 16) & 0x1f;
}

// OPTIONAL_REG (5, 21, GP)
void lop_v(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 21) & 0x1f;
}

// REG (5, 0, GP);
void lop_plusz(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = l & 0x1f;
}

// REG (5, 16, VEC)
void lop_plusZ(unsigned long l, op_t &x)
{
  x.type = o_reg;
  x.reg = (l >> 16) & 0x1f;
}

// D - REG (5, 6, FP);
void lop_D(unsigned long l, op_t &x)
{
  unsigned long rfp = (l >> 6) & 0x1f;
  x.type = o_reg;
  // floating point registers start with index 32
  x.reg = rfp + 32;
}

// case 'S': REG (5, 11, FP);
void lop_S(unsigned long l, op_t &x)
{
  unsigned long rfp = (l >> 11) & 0x1f;
  x.type = o_reg;
  // floating point registers start with index 32
  x.reg = rfp + 32;
}

// case 'T': REG (5, 16, FP);
void lop_T(unsigned long l, op_t &x)
{
  unsigned long rfp = (l >> 16) & 0x1f;
  x.type = o_reg;
  // floating point registers start with index 32
  x.reg = rfp + 32;
}

#include "gen.inc"

struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  ea_t ea = 0; // current address within the instruction
  int latch = 0;
  netnode nec_node;
  bool hooked = false;

  plugin_ctx_t();
  ~plugin_ctx_t()
  { }

  // This function is called when the user invokes the plugin.
  virtual bool idaapi run(size_t) override;
  // This function is called upon some events.
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  size_t ana(insn_t &insn);
};

ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    case processor_t::ev_ana_insn:
      {
        insn_t *insn = va_arg(va, insn_t *);
        ea = insn->ea;
        unsigned long val = _byteswap_ulong(get_dword(ea));
        size_t length = loongson_ana(val, insn);
        if ( !latch )
        {
          msg("%a: %X, len %d\n", ea, val, length);
          latch++;
        }
        if ( length )
        {
          insn->size = (uint16)length;
          return insn->size;       // event processed
        }
      }
      break;
    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const insn_t &insn = ctx->insn;
        if ( insn.itype >= CUSTOM_INSN_ITYPE && insn.itype < CUSTOM_INSN_ITYPE + _countof(loong_op_names) )
        {
          ctx->out_line(loong_op_names[insn.itype - CUSTOM_INSN_ITYPE] , COLOR_INSN);
          ctx->out_symbol(' ');
          return 1;
        }
      }
      break;
  }
  return 0;                     // event is not processed
}

plugin_ctx_t::plugin_ctx_t()
{
  nec_node.create(node_name);
  hooked = nec_node.altval(0) != 0;
  if ( hooked )
  {
    hook_event_listener(HT_IDP, this);
    msg("loongson processor extender is enabled\n");
  }
}

bool idaapi plugin_ctx_t::run(size_t)
{
  if ( hooked )
    unhook_event_listener(HT_IDP, this);
  else
    hook_event_listener(HT_IDP, this);
  hooked = !hooked;
  nec_node.create(node_name);
  nec_node.altset(0, hooked);
  info("AUTOHIDE NONE\n"
       "loongson processor extender now is %s", hooked ? "enabled" : "disabled");
  return true;
}

static plugmod_t *idaapi loong_init()
{
  processor_t &ph = PH;
  if ( ph.id != PLFM_MIPS )
    return nullptr;
  return new plugin_ctx_t;
}

static const char comment[] = "loongson processor extender for mips";
static const char help[] =
  "loongson processor extender for mips\n"
  "\n"
  "supported lcam, lext & lmmi group of instructions.\n";
static const char desired_name[] = "loongson processor extender for mips";
static const char desired_hotkey[] = "";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC           // this is a processor extension plugin
| PLUGIN_MULTI,         // this plugin can work with multiple idbs in parallel
  loong_init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin. not used.
  help,                 // multiline help about the plugin. not used.
  desired_name,         // the preferred short name of the plugin
  desired_hotkey        // the preferred hotkey to run the plugin
};
