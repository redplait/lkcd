#pragma once
//------------------------------------------------------------------
DECLARE_PROC_LISTENER(idb_listener_t, struct loongson_t);

struct loongson_t : public procmod_t
{
  netnode helper;
  idb_listener_t idb_listener = idb_listener_t(*this);
  ushort idpflags = 0;
  bool flow = false;
  char show_sizer = -1;

  virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;
};