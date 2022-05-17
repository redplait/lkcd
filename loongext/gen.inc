// this file was generated with script data/loong.pl
// do not edit it
enum loong_insn_type_t {
 LOONG_campi = CUSTOM_INSN_ITYPE,
 LOONG_campv,
 LOONG_camwi,
 LOONG_ramri,
 LOONG_gsle,
 LOONG_gsgt,
 LOONG_gslble,
 LOONG_gslbgt,
 LOONG_gslhle,
 LOONG_gslhgt,
 LOONG_gslwle,
 LOONG_gslwgt,
 LOONG_gsldle,
 LOONG_gsldgt,
 LOONG_gssble,
 LOONG_gssbgt,
 LOONG_gsshle,
 LOONG_gsshgt,
 LOONG_gsswle,
 LOONG_gsswgt,
 LOONG_gssdle,
 LOONG_gssdgt,
 LOONG_gslwlec1,
 LOONG_gslwgtc1,
 LOONG_gsldlec1,
 LOONG_gsldgtc1,
 LOONG_gsswlec1,
 LOONG_gsswgtc1,
 LOONG_gssdlec1,
 LOONG_gssdgtc1,
 LOONG_gslwlc1,
 LOONG_gslwrc1,
 LOONG_gsldlc1,
 LOONG_gsldrc1,
 LOONG_gsswlc1,
 LOONG_gsswrc1,
 LOONG_gssdlc1,
 LOONG_gssdrc1,
 LOONG_gslbx,
 LOONG_gslhx,
 LOONG_gslwx,
 LOONG_gsldx,
 LOONG_gssbx,
 LOONG_gsshx,
 LOONG_gsswx,
 LOONG_gssdx,
 LOONG_gslwxc1,
 LOONG_gsldxc1,
 LOONG_gsswxc1,
 LOONG_gssdxc1,
 LOONG_gslq,
 LOONG_gssq,
 LOONG_gslqc1,
 LOONG_gssqc1,
 LOONG_cto,
 LOONG_ctz,
 LOONG_dcto,
 LOONG_dctz,
 LOONG_movnz,
 LOONG_sle,
 LOONG_sleu,
 LOONG_gsmult,
 LOONG_gsmultu,
 LOONG_gsdmult,
 LOONG_gsdmultu,
 LOONG_gsdiv,
 LOONG_gsdivu,
 LOONG_gsddiv,
 LOONG_gsddivu,
 LOONG_gsmod,
 LOONG_gsmodu,
 LOONG_gsdmod,
 LOONG_gsdmodu,
 LOONG_packsshb,
 LOONG_packsswh,
 LOONG_packushb,
 LOONG_paddd,
 LOONG_paddusb,
 LOONG_paddush,
 LOONG_pandn,
 LOONG_pavgb,
 LOONG_pavgh,
 LOONG_pcmpeqb,
 LOONG_pcmpeqh,
 LOONG_pcmpeqw,
 LOONG_pcmpgtb,
 LOONG_pcmpgth,
 LOONG_pcmpgtw,
 LOONG_pextrh,
 LOONG_pinsrh_0,
 LOONG_pinsrh_1,
 LOONG_pinsrh_2,
 LOONG_pinsrh_3,
 LOONG_pmaddhw,
 LOONG_pmaxsh,
 LOONG_pmaxub,
 LOONG_pminsh,
 LOONG_pminub,
 LOONG_pmovmskb,
 LOONG_pmulhuh,
 LOONG_pmulhh,
 LOONG_pmullh,
 LOONG_pmuluw,
 LOONG_pasubub,
 LOONG_biadd,
 LOONG_pshufh,
 LOONG_psubd,
 LOONG_psubusb,
 LOONG_psubush,
 LOONG_punpckhbh,
 LOONG_punpckhhw,
 LOONG_punpckhwd,
 LOONG_punpcklbh,
 LOONG_punpcklhw,
 LOONG_punpcklwd,
 LOONG_sequ,
};

const char *loong_op_names[] = {
 "campi", /* LOONG_campi */
 "campv", /* LOONG_campv */
 "camwi", /* LOONG_camwi */
 "ramri", /* LOONG_ramri */
 "gsle", /* LOONG_gsle */
 "gsgt", /* LOONG_gsgt */
 "gslble", /* LOONG_gslble */
 "gslbgt", /* LOONG_gslbgt */
 "gslhle", /* LOONG_gslhle */
 "gslhgt", /* LOONG_gslhgt */
 "gslwle", /* LOONG_gslwle */
 "gslwgt", /* LOONG_gslwgt */
 "gsldle", /* LOONG_gsldle */
 "gsldgt", /* LOONG_gsldgt */
 "gssble", /* LOONG_gssble */
 "gssbgt", /* LOONG_gssbgt */
 "gsshle", /* LOONG_gsshle */
 "gsshgt", /* LOONG_gsshgt */
 "gsswle", /* LOONG_gsswle */
 "gsswgt", /* LOONG_gsswgt */
 "gssdle", /* LOONG_gssdle */
 "gssdgt", /* LOONG_gssdgt */
 "gslwlec1", /* LOONG_gslwlec1 */
 "gslwgtc1", /* LOONG_gslwgtc1 */
 "gsldlec1", /* LOONG_gsldlec1 */
 "gsldgtc1", /* LOONG_gsldgtc1 */
 "gsswlec1", /* LOONG_gsswlec1 */
 "gsswgtc1", /* LOONG_gsswgtc1 */
 "gssdlec1", /* LOONG_gssdlec1 */
 "gssdgtc1", /* LOONG_gssdgtc1 */
 "gslwlc1", /* LOONG_gslwlc1 */
 "gslwrc1", /* LOONG_gslwrc1 */
 "gsldlc1", /* LOONG_gsldlc1 */
 "gsldrc1", /* LOONG_gsldrc1 */
 "gsswlc1", /* LOONG_gsswlc1 */
 "gsswrc1", /* LOONG_gsswrc1 */
 "gssdlc1", /* LOONG_gssdlc1 */
 "gssdrc1", /* LOONG_gssdrc1 */
 "gslbx", /* LOONG_gslbx */
 "gslhx", /* LOONG_gslhx */
 "gslwx", /* LOONG_gslwx */
 "gsldx", /* LOONG_gsldx */
 "gssbx", /* LOONG_gssbx */
 "gsshx", /* LOONG_gsshx */
 "gsswx", /* LOONG_gsswx */
 "gssdx", /* LOONG_gssdx */
 "gslwxc1", /* LOONG_gslwxc1 */
 "gsldxc1", /* LOONG_gsldxc1 */
 "gsswxc1", /* LOONG_gsswxc1 */
 "gssdxc1", /* LOONG_gssdxc1 */
 "gslq", /* LOONG_gslq */
 "gssq", /* LOONG_gssq */
 "gslqc1", /* LOONG_gslqc1 */
 "gssqc1", /* LOONG_gssqc1 */
 "cto", /* LOONG_cto */
 "ctz", /* LOONG_ctz */
 "dcto", /* LOONG_dcto */
 "dctz", /* LOONG_dctz */
 "movnz", /* LOONG_movnz */
 "sle", /* LOONG_sle */
 "sleu", /* LOONG_sleu */
 "gsmult", /* LOONG_gsmult */
 "gsmultu", /* LOONG_gsmultu */
 "gsdmult", /* LOONG_gsdmult */
 "gsdmultu", /* LOONG_gsdmultu */
 "gsdiv", /* LOONG_gsdiv */
 "gsdivu", /* LOONG_gsdivu */
 "gsddiv", /* LOONG_gsddiv */
 "gsddivu", /* LOONG_gsddivu */
 "gsmod", /* LOONG_gsmod */
 "gsmodu", /* LOONG_gsmodu */
 "gsdmod", /* LOONG_gsdmod */
 "gsdmodu", /* LOONG_gsdmodu */
 "packsshb", /* LOONG_packsshb */
 "packsswh", /* LOONG_packsswh */
 "packushb", /* LOONG_packushb */
 "paddd", /* LOONG_paddd */
 "paddusb", /* LOONG_paddusb */
 "paddush", /* LOONG_paddush */
 "pandn", /* LOONG_pandn */
 "pavgb", /* LOONG_pavgb */
 "pavgh", /* LOONG_pavgh */
 "pcmpeqb", /* LOONG_pcmpeqb */
 "pcmpeqh", /* LOONG_pcmpeqh */
 "pcmpeqw", /* LOONG_pcmpeqw */
 "pcmpgtb", /* LOONG_pcmpgtb */
 "pcmpgth", /* LOONG_pcmpgth */
 "pcmpgtw", /* LOONG_pcmpgtw */
 "pextrh", /* LOONG_pextrh */
 "pinsrh_0", /* LOONG_pinsrh_0 */
 "pinsrh_1", /* LOONG_pinsrh_1 */
 "pinsrh_2", /* LOONG_pinsrh_2 */
 "pinsrh_3", /* LOONG_pinsrh_3 */
 "pmaddhw", /* LOONG_pmaddhw */
 "pmaxsh", /* LOONG_pmaxsh */
 "pmaxub", /* LOONG_pmaxub */
 "pminsh", /* LOONG_pminsh */
 "pminub", /* LOONG_pminub */
 "pmovmskb", /* LOONG_pmovmskb */
 "pmulhuh", /* LOONG_pmulhuh */
 "pmulhh", /* LOONG_pmulhh */
 "pmullh", /* LOONG_pmullh */
 "pmuluw", /* LOONG_pmuluw */
 "pasubub", /* LOONG_pasubub */
 "biadd", /* LOONG_biadd */
 "pshufh", /* LOONG_pshufh */
 "psubd", /* LOONG_psubd */
 "psubusb", /* LOONG_psubusb */
 "psubush", /* LOONG_psubush */
 "punpckhbh", /* LOONG_punpckhbh */
 "punpckhhw", /* LOONG_punpckhhw */
 "punpckhwd", /* LOONG_punpckhwd */
 "punpcklbh", /* LOONG_punpcklbh */
 "punpcklhw", /* LOONG_punpcklhw */
 "punpcklwd", /* LOONG_punpcklwd */
 "sequ", /* LOONG_sequ */
};

int loongson_ana(unsigned long value, insn_t *insn)
{
 switch(value & 0xFFFF003F)
 {
  case 0x46A00005:
    insn->itype = LOONG_pmovmskb; // D,S
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
  return 4;
  case 0x4BA0000F:
    insn->itype = LOONG_pmovmskb; // D,S
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
  return 4;
  case 0x46800005:
    insn->itype = LOONG_biadd; // D,S
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
  return 4;
  case 0x4B80000F:
    insn->itype = LOONG_biadd; // D,S
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
  return 4;
 }
 switch(value & 0xFFE007FF)
 {
  case 0x46A0003E:
    insn->itype = LOONG_sle; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
  case 0x4BA0000E:
    insn->itype = LOONG_sle; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
  case 0x4680003E:
    insn->itype = LOONG_sleu; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
  case 0x4B80000E:
    insn->itype = LOONG_sleu; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
  case 0x46800032:
    insn->itype = LOONG_sequ; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
  case 0x4B80000C:
    insn->itype = LOONG_sequ; // S,T
    lop_S(value, insn->Op1);
    lop_T(value, insn->Op2);
  return 4;
 }
 switch(value & 0xFFE0003F)
 {
  case 0x47400002:
    insn->itype = LOONG_packsshb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B400002:
    insn->itype = LOONG_packsshb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47200002:
    insn->itype = LOONG_packsswh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200002:
    insn->itype = LOONG_packsswh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47600002:
    insn->itype = LOONG_packushb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B600002:
    insn->itype = LOONG_packushb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47E00000:
    insn->itype = LOONG_paddd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BE00000:
    insn->itype = LOONG_paddd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47A00000:
    insn->itype = LOONG_paddusb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA00000:
    insn->itype = LOONG_paddusb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47200000:
    insn->itype = LOONG_paddush; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200000:
    insn->itype = LOONG_paddush; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47E00002:
    insn->itype = LOONG_pandn; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BE00002:
    insn->itype = LOONG_pandn; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46600000:
    insn->itype = LOONG_pavgb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200008:
    insn->itype = LOONG_pavgb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46400000:
    insn->itype = LOONG_pavgh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B000008:
    insn->itype = LOONG_pavgh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46C00001:
    insn->itype = LOONG_pcmpeqb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B800009:
    insn->itype = LOONG_pcmpeqb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46800001:
    insn->itype = LOONG_pcmpeqh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B400009:
    insn->itype = LOONG_pcmpeqh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46400001:
    insn->itype = LOONG_pcmpeqw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B000009:
    insn->itype = LOONG_pcmpeqw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46E00001:
    insn->itype = LOONG_pcmpgtb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA00009:
    insn->itype = LOONG_pcmpgtb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46A00001:
    insn->itype = LOONG_pcmpgth; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B600009:
    insn->itype = LOONG_pcmpgth; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46600001:
    insn->itype = LOONG_pcmpgtw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200009:
    insn->itype = LOONG_pcmpgtw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x45C00002:
    insn->itype = LOONG_pextrh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B40000E:
    insn->itype = LOONG_pextrh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47800003:
    insn->itype = LOONG_pinsrh_0; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B800003:
    insn->itype = LOONG_pinsrh_0; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47A00003:
    insn->itype = LOONG_pinsrh_1; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA00003:
    insn->itype = LOONG_pinsrh_1; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47C00003:
    insn->itype = LOONG_pinsrh_2; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BC00003:
    insn->itype = LOONG_pinsrh_2; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47E00003:
    insn->itype = LOONG_pinsrh_3; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BE00003:
    insn->itype = LOONG_pinsrh_3; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x45E00002:
    insn->itype = LOONG_pmaddhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B60000E:
    insn->itype = LOONG_pmaddhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46800000:
    insn->itype = LOONG_pmaxsh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B400008:
    insn->itype = LOONG_pmaxsh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46C00000:
    insn->itype = LOONG_pmaxub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B800008:
    insn->itype = LOONG_pmaxub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46A00000:
    insn->itype = LOONG_pminsh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B600008:
    insn->itype = LOONG_pminsh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46E00000:
    insn->itype = LOONG_pminub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA00008:
    insn->itype = LOONG_pminub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46E00002:
    insn->itype = LOONG_pmulhuh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA0000A:
    insn->itype = LOONG_pmulhuh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46A00002:
    insn->itype = LOONG_pmulhh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B60000A:
    insn->itype = LOONG_pmulhh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46800002:
    insn->itype = LOONG_pmullh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B40000A:
    insn->itype = LOONG_pmullh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46C00002:
    insn->itype = LOONG_pmuluw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B80000A:
    insn->itype = LOONG_pmuluw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x45A00001:
    insn->itype = LOONG_pasubub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B20000D:
    insn->itype = LOONG_pasubub; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47000002:
    insn->itype = LOONG_pshufh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B000002:
    insn->itype = LOONG_pshufh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47E00001:
    insn->itype = LOONG_psubd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BE00001:
    insn->itype = LOONG_psubd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47A00001:
    insn->itype = LOONG_psubusb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA00001:
    insn->itype = LOONG_psubusb; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47200001:
    insn->itype = LOONG_psubush; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200001:
    insn->itype = LOONG_psubush; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47600003:
    insn->itype = LOONG_punpckhbh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B600003:
    insn->itype = LOONG_punpckhbh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47200003:
    insn->itype = LOONG_punpckhhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B200003:
    insn->itype = LOONG_punpckhhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46E00003:
    insn->itype = LOONG_punpckhwd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4BA0000B:
    insn->itype = LOONG_punpckhwd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47400003:
    insn->itype = LOONG_punpcklbh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B400003:
    insn->itype = LOONG_punpcklbh; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x47000003:
    insn->itype = LOONG_punpcklhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B000003:
    insn->itype = LOONG_punpcklhw; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x46C00003:
    insn->itype = LOONG_punpcklwd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
  case 0x4B80000B:
    insn->itype = LOONG_punpcklwd; // D,S,T
    lop_D(value, insn->Op1);
    lop_S(value, insn->Op2);
    lop_T(value, insn->Op3);
  return 4;
 }
 switch(value & 0xFC1F07FF)
 {
  case 0x70000075:
    insn->itype = LOONG_campi; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x70000035:
    insn->itype = LOONG_campv; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x700000F5:
    insn->itype = LOONG_ramri; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x70000062:
    insn->itype = LOONG_cto; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x70000022:
    insn->itype = LOONG_ctz; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x700000E2:
    insn->itype = LOONG_dcto; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
  case 0x700000A2:
    insn->itype = LOONG_dctz; // d,s
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
  return 4;
 }
 switch(value & 0xFC00FFFF)
 {
  case 0x70000026:
    insn->itype = LOONG_gsle; // s,t
    lop_s(value, insn->Op1);
    lop_t(value, insn->Op2);
  return 4;
  case 0x70000027:
    insn->itype = LOONG_gsgt; // s,t
    lop_s(value, insn->Op1);
    lop_t(value, insn->Op2);
  return 4;
 }
 switch(value & 0xFC00C03F)
 {
  case 0xC8000004:
    insn->itype = LOONG_gslwlc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xC8000005:
    insn->itype = LOONG_gslwrc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xC8000006:
    insn->itype = LOONG_gsldlc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xC8000007:
    insn->itype = LOONG_gsldrc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xE8000004:
    insn->itype = LOONG_gsswlc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xE8000005:
    insn->itype = LOONG_gsswrc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xE8000006:
    insn->itype = LOONG_gssdlc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
  case 0xE8000007:
    insn->itype = LOONG_gssdrc1; // T,+a(b)
    lop_T(value, insn->Op1);
    lop_plusa(value, insn->Op2);
  return 4;
 }
 switch(value & 0xFC008020)
 {
  case 0xC8000020:
    insn->itype = LOONG_gslq; // +z,t,+c(b)
    lop_plusz(value, insn->Op1);
    lop_t(value, insn->Op2);
    lop_plusc(value, insn->Op3);
  return 4;
  case 0xE8000020:
    insn->itype = LOONG_gssq; // +z,t,+c(b)
    lop_plusz(value, insn->Op1);
    lop_t(value, insn->Op2);
    lop_plusc(value, insn->Op3);
  return 4;
  case 0xC8008020:
    insn->itype = LOONG_gslqc1; // +Z,T,+c(b)
    lop_plusZ(value, insn->Op1);
    lop_T(value, insn->Op2);
    lop_plusc(value, insn->Op3);
  return 4;
  case 0xE8008020:
    insn->itype = LOONG_gssqc1; // +Z,T,+c(b)
    lop_plusZ(value, insn->Op1);
    lop_T(value, insn->Op2);
    lop_plusc(value, insn->Op3);
  return 4;
 }
 switch(value & 0xFC0007FF)
 {
  case 0x700000B5:
    insn->itype = LOONG_camwi; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0xC8000010:
    insn->itype = LOONG_gslble; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000011:
    insn->itype = LOONG_gslbgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000012:
    insn->itype = LOONG_gslhle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000013:
    insn->itype = LOONG_gslhgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000014:
    insn->itype = LOONG_gslwle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000015:
    insn->itype = LOONG_gslwgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000016:
    insn->itype = LOONG_gsldle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000017:
    insn->itype = LOONG_gsldgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000010:
    insn->itype = LOONG_gssble; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000011:
    insn->itype = LOONG_gssbgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000012:
    insn->itype = LOONG_gsshle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000013:
    insn->itype = LOONG_gsshgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000014:
    insn->itype = LOONG_gsswle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000015:
    insn->itype = LOONG_gsswgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000016:
    insn->itype = LOONG_gssdle; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE8000017:
    insn->itype = LOONG_gssdgt; // t,b,d
    lop_t(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000018:
    insn->itype = LOONG_gslwlec1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC8000019:
    insn->itype = LOONG_gslwgtc1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC800001A:
    insn->itype = LOONG_gsldlec1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xC800001B:
    insn->itype = LOONG_gsldgtc1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE800001C:
    insn->itype = LOONG_gsswlec1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE800001D:
    insn->itype = LOONG_gsswgtc1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE800001E:
    insn->itype = LOONG_gssdlec1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xE800001F:
    insn->itype = LOONG_gssdgtc1; // T,b,d
    lop_T(value, insn->Op1);
    lop_b(value, insn->Op2);
    lop_d(value, insn->Op3);
  return 4;
  case 0xB:
    insn->itype = LOONG_movnz; // d,v,t
    lop_d(value, insn->Op1);
    lop_v(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000010:
    insn->itype = LOONG_gsmult; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000012:
    insn->itype = LOONG_gsmultu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000011:
    insn->itype = LOONG_gsdmult; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000013:
    insn->itype = LOONG_gsdmultu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000014:
    insn->itype = LOONG_gsdiv; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000016:
    insn->itype = LOONG_gsdivu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000015:
    insn->itype = LOONG_gsddiv; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x70000017:
    insn->itype = LOONG_gsddivu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x7000001C:
    insn->itype = LOONG_gsmod; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x7000001E:
    insn->itype = LOONG_gsmodu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x7000001D:
    insn->itype = LOONG_gsdmod; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
  case 0x7000001F:
    insn->itype = LOONG_gsdmodu; // d,s,t
    lop_d(value, insn->Op1);
    lop_s(value, insn->Op2);
    lop_t(value, insn->Op3);
  return 4;
 }
 switch(value & 0xFC000007)
 {
  case 0xD8000000:
    insn->itype = LOONG_gslbx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xD8000001:
    insn->itype = LOONG_gslhx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xD8000002:
    insn->itype = LOONG_gslwx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xD8000003:
    insn->itype = LOONG_gsldx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000000:
    insn->itype = LOONG_gssbx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000001:
    insn->itype = LOONG_gsshx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000002:
    insn->itype = LOONG_gsswx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000003:
    insn->itype = LOONG_gssdx; // t,+b(b,d)
    lop_t(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xD8000006:
    insn->itype = LOONG_gslwxc1; // T,+b(b,d)
    lop_T(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xD8000007:
    insn->itype = LOONG_gsldxc1; // T,+b(b,d)
    lop_T(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000006:
    insn->itype = LOONG_gsswxc1; // T,+b(b,d)
    lop_T(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
  case 0xF8000007:
    insn->itype = LOONG_gssdxc1; // T,+b(b,d)
    lop_T(value, insn->Op1);
    lop_plusb(value, insn->Op2);
    lop_b(value, insn->Op3);
    lop_d(value, insn->Op4);
  return 4;
 }
 return 0;
}
