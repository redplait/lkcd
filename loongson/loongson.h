#pragma once
//------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct loongson_t);

struct loongson_t : public procmod_t
{
  netnode helper;
  idb_listener_t idb_listener = idb_listener_t(*this);
#define USE_RETN 1
  ushort idpflags = USE_RETN;

  inline bool use_retn() const
  {
    return (idpflags & USE_RETN);
  }

  const char *set_idp_options(
        const char *keyword,
        int value_type,
        const void *value,
        bool idb_loaded);
  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
};