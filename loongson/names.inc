const instruc_t Instructions[] = {
{ "clo.w", CF_CHG1 | CF_USE2 }, /* Loong_clo_w */
{ "clz.w", CF_CHG1 | CF_USE2 }, /* Loong_clz_w */
{ "cto.w", CF_CHG1 | CF_USE2 }, /* Loong_cto_w */
{ "ctz.w", CF_CHG1 | CF_USE2 }, /* Loong_ctz_w */
{ "clo.d", CF_CHG1 | CF_USE2 }, /* Loong_clo_d */
{ "clz.d", CF_CHG1 | CF_USE2 }, /* Loong_clz_d */
{ "cto.d", CF_CHG1 | CF_USE2 }, /* Loong_cto_d */
{ "ctz.d", CF_CHG1 | CF_USE2 }, /* Loong_ctz_d */
{ "revb.2h", CF_CHG1 | CF_USE2 }, /* Loong_revb_2h */
{ "revb.4h", CF_CHG1 | CF_USE2 }, /* Loong_revb_4h */
{ "revb.2w", CF_CHG1 | CF_USE2 }, /* Loong_revb_2w */
{ "revb.d", CF_CHG1 | CF_USE2 }, /* Loong_revb_d */
{ "revh.2w", CF_CHG1 | CF_USE2 }, /* Loong_revh_2w */
{ "revh.d", CF_CHG1 | CF_USE2 }, /* Loong_revh_d */
{ "bitrev.4b", CF_CHG1 | CF_USE2 }, /* Loong_bitrev_4b */
{ "bitrev.8b", CF_CHG1 | CF_USE2 }, /* Loong_bitrev_8b */
{ "bitrev.w", CF_CHG1 | CF_USE2 }, /* Loong_bitrev_w */
{ "bitrev.d", CF_CHG1 | CF_USE2 }, /* Loong_bitrev_d */
{ "ext.w.h", CF_CHG1 | CF_USE2 }, /* Loong_ext_w_h */
{ "ext.w.b", CF_CHG1 | CF_USE2 }, /* Loong_ext_w_b */
{ "rdtimel.w", CF_CHG1 | CF_USE2 }, /* Loong_rdtimel_w */
{ "rdtimeh.w", CF_CHG1 | CF_USE2 }, /* Loong_rdtimeh_w */
{ "rdtime.d", CF_CHG1 | CF_USE2 }, /* Loong_rdtime_d */
{ "cpucfg", CF_CHG1 | CF_USE2 }, /* Loong_cpucfg */
{ "asrtle.d", CF_USE1 | CF_USE2 }, /* Loong_asrtle_d */
{ "asrtgt.d", CF_USE1 | CF_USE2 }, /* Loong_asrtgt_d */
{ "alsl.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_SHFT }, /* Loong_alsl_w */
{ "alsl.wu", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_SHFT }, /* Loong_alsl_wu */
{ "bytepick.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bytepick_w */
{ "bytepick.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bytepick_d */
{ "add.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_add_w */
{ "add.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_add_d */
{ "sub.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sub_w */
{ "sub.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sub_d */
{ "slt", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_slt */
{ "sltu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sltu */
{ "maskeqz", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_maskeqz */
{ "masknez", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_masknez */
{ "nor", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_nor */
{ "and", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_and */
{ "or", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_or */
{ "xor", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_xor */
{ "orn", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_orn */
{ "andn", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_andn */
{ "sll.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_sll_w */
{ "srl.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srl_w */
{ "sra.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_sra_w */
{ "sll.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_sll_d */
{ "srl.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srl_d */
{ "sra.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_sra_d */
{ "rotr.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_rotr_w */
{ "rotr.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_rotr_d */
{ "mul.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mul_w */
{ "mulh.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulh_w */
{ "mulh.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulh_wu */
{ "mul.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mul_d */
{ "mulh.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulh_d */
{ "mulh.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulh_du */
{ "mulw.d.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulw_d_w */
{ "mulw.d.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mulw_d_wu */
{ "div.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_div_w */
{ "mod.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mod_w */
{ "div.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_div_wu */
{ "mod.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mod_wu */
{ "div.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_div_d */
{ "mod.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mod_d */
{ "div.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_div_du */
{ "mod.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_mod_du */
{ "crc.w.b.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crc_w_b_w */
{ "crc.w.h.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crc_w_h_w */
{ "crc.w.w.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crc_w_w_w */
{ "crc.w.d.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crc_w_d_w */
{ "crcc.w.b.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crcc_w_b_w */
{ "crcc.w.h.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crcc_w_h_w */
{ "crcc.w.w.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crcc_w_w_w */
{ "crcc.w.d.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_crcc_w_d_w */
{ "break", CF_STOP }, /* Loong_break */
{ "syscall", 0 }, /* Loong_syscall */
{ "alsl.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_SHFT }, /* Loong_alsl_d */
{ "slli.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_slli_w */
{ "slli.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_slli_d */
{ "srli.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srli_w */
{ "srli.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srli_d */
{ "srai.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srai_w */
{ "srai.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT }, /* Loong_srai_d */
{ "rotri.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_rotri_w */
{ "rotri.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_rotri_d */
{ "bstrins.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bstrins_w */
{ "bstrpick.w", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bstrpick_w */
{ "bstrins.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bstrins_d */
{ "bstrpick.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_bstrpick_d */
{ "fadd.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fadd_s */
{ "fadd.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fadd_d */
{ "fsub.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fsub_s */
{ "fsub.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fsub_d */
{ "fmul.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmul_s */
{ "fmul.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmul_d */
{ "fdiv.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fdiv_s */
{ "fdiv.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fdiv_d */
{ "fmax.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmax_s */
{ "fmax.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmax_d */
{ "fmin.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmin_s */
{ "fmin.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmin_d */
{ "fmaxa.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmaxa_s */
{ "fmaxa.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmaxa_d */
{ "fmina.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmina_s */
{ "fmina.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fmina_d */
{ "fscaleb.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fscaleb_s */
{ "fscaleb.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fscaleb_d */
{ "fcopysign.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fcopysign_s */
{ "fcopysign.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fcopysign_d */
{ "fabs.s", CF_CHG1 | CF_USE2 }, /* Loong_fabs_s */
{ "fabs.d", CF_CHG1 | CF_USE2 }, /* Loong_fabs_d */
{ "fneg.s", CF_CHG1 | CF_USE2 }, /* Loong_fneg_s */
{ "fneg.d", CF_CHG1 | CF_USE2 }, /* Loong_fneg_d */
{ "flogb.s", CF_CHG1 | CF_USE2 }, /* Loong_flogb_s */
{ "flogb.d", CF_CHG1 | CF_USE2 }, /* Loong_flogb_d */
{ "fclass.s", CF_CHG1 | CF_USE2 }, /* Loong_fclass_s */
{ "fclass.d", CF_CHG1 | CF_USE2 }, /* Loong_fclass_d */
{ "fsqrt.s", CF_CHG1 | CF_USE2 }, /* Loong_fsqrt_s */
{ "fsqrt.d", CF_CHG1 | CF_USE2 }, /* Loong_fsqrt_d */
{ "frecip.s", CF_CHG1 | CF_USE2 }, /* Loong_frecip_s */
{ "frecip.d", CF_CHG1 | CF_USE2 }, /* Loong_frecip_d */
{ "frsqrt.s", CF_CHG1 | CF_USE2 }, /* Loong_frsqrt_s */
{ "frsqrt.d", CF_CHG1 | CF_USE2 }, /* Loong_frsqrt_d */
{ "fmov.s", CF_CHG1 | CF_USE2 }, /* Loong_fmov_s */
{ "fmov.d", CF_CHG1 | CF_USE2 }, /* Loong_fmov_d */
{ "movgr2fr.w", CF_CHG1 | CF_USE2 }, /* Loong_movgr2fr_w */
{ "movgr2fr.d", CF_CHG1 | CF_USE2 }, /* Loong_movgr2fr_d */
{ "movgr2frh.w", CF_CHG1 | CF_USE2 }, /* Loong_movgr2frh_w */
{ "movfr2gr.s", CF_CHG1 | CF_USE2 }, /* Loong_movfr2gr_s */
{ "movfr2gr.d", CF_CHG1 | CF_USE2 }, /* Loong_movfr2gr_d */
{ "movfrh2gr.s", CF_CHG1 | CF_USE2 }, /* Loong_movfrh2gr_s */
{ "movgr2fcsr", CF_CHG1 | CF_USE2 }, /* Loong_movgr2fcsr */
{ "movfcsr2gr", CF_CHG1 | CF_USE2 }, /* Loong_movfcsr2gr */
{ "movfr2cf", CF_CHG1 | CF_USE2 }, /* Loong_movfr2cf */
{ "movcf2fr", CF_CHG1 | CF_USE2 }, /* Loong_movcf2fr */
{ "movgr2cf", CF_CHG1 | CF_USE2 }, /* Loong_movgr2cf */
{ "movcf2gr", CF_CHG1 | CF_USE2 }, /* Loong_movcf2gr */
{ "fcvt.s.d", CF_CHG1 | CF_USE2 }, /* Loong_fcvt_s_d */
{ "fcvt.d.s", CF_CHG1 | CF_USE2 }, /* Loong_fcvt_d_s */
{ "ftintrm.w.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrm_w_s */
{ "ftintrm.w.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrm_w_d */
{ "ftintrm.l.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrm_l_s */
{ "ftintrm.l.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrm_l_d */
{ "ftintrp.w.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrp_w_s */
{ "ftintrp.w.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrp_w_d */
{ "ftintrp.l.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrp_l_s */
{ "ftintrp.l.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrp_l_d */
{ "ftintrz.w.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrz_w_s */
{ "ftintrz.w.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrz_w_d */
{ "ftintrz.l.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrz_l_s */
{ "ftintrz.l.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrz_l_d */
{ "ftintrne.w.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrne_w_s */
{ "ftintrne.w.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrne_w_d */
{ "ftintrne.l.s", CF_CHG1 | CF_USE2 }, /* Loong_ftintrne_l_s */
{ "ftintrne.l.d", CF_CHG1 | CF_USE2 }, /* Loong_ftintrne_l_d */
{ "ftint.w.s", CF_CHG1 | CF_USE2 }, /* Loong_ftint_w_s */
{ "ftint.w.d", CF_CHG1 | CF_USE2 }, /* Loong_ftint_w_d */
{ "ftint.l.s", CF_CHG1 | CF_USE2 }, /* Loong_ftint_l_s */
{ "ftint.l.d", CF_CHG1 | CF_USE2 }, /* Loong_ftint_l_d */
{ "ffint.s.w", CF_CHG1 | CF_USE2 }, /* Loong_ffint_s_w */
{ "ffint.s.l", CF_CHG1 | CF_USE2 }, /* Loong_ffint_s_l */
{ "ffint.d.w", CF_CHG1 | CF_USE2 }, /* Loong_ffint_d_w */
{ "ffint.d.l", CF_CHG1 | CF_USE2 }, /* Loong_ffint_d_l */
{ "frint.s", CF_CHG1 | CF_USE2 }, /* Loong_frint_s */
{ "frint.d", CF_CHG1 | CF_USE2 }, /* Loong_frint_d */
{ "slti", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_slti */
{ "sltui", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sltui */
{ "addi.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_addi_w */
{ "addi.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_addi_d */
{ "lu52i.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_lu52i_d */
{ "andi", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_andi */
{ "ori", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ori */
{ "xori", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_xori */
{ "fmadd.s", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fmadd_s */
{ "fmadd.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fmadd_d */
{ "fmsub.s", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fmsub_s */
{ "fmsub.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fmsub_d */
{ "fnmadd.s", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fnmadd_s */
{ "fnmadd.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fnmadd_d */
{ "fnmsub.s", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fnmsub_s */
{ "fnmsub.d", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fnmsub_d */
{ "fsel", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, /* Loong_fsel */
{ "addu16i.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_addu16i_d */
{ "lu12i.w", CF_CHG1 | CF_USE2 }, /* Loong_lu12i_w */
{ "lu32i.d", CF_CHG1 | CF_USE2 }, /* Loong_lu32i_d */
{ "pcaddi",  CF_CHG1 | CF_USE2 }, /* Loong_pcaddi */
{ "pcalau12i", CF_CHG1 | CF_USE2 }, /* Loong_pcalau12i */
{ "pcaddu12i", CF_CHG1 | CF_USE2 }, /* Loong_pcaddu12i */
{ "pcaddu18i", CF_CHG1 | CF_USE2 }, /* Loong_pcaddu18i */
{ "ll.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ll_w */
{ "sc.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sc_w */
{ "ll.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ll_d */
{ "sc.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_sc_d */
{ "ldptr.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldptr_w */
{ "stptr.w", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stptr_w */
{ "ldptr.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldptr_d */
{ "stptr.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stptr_d */
{ "ld.b", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_b */
{ "ld.h", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_h */
{ "ld.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_w */
{ "ld.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_d */
{ "st.b", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_st_b */
{ "st.h", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_st_h */
{ "st.w", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_st_w */
{ "st.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_st_d */
{ "ld.bu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_bu */
{ "ld.hu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_hu */
{ "ld.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ld_wu */
{ "preld", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_preld */
{ "fld.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fld_s */
{ "fst.s", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fst_s */
{ "fld.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fld_d */
{ "fst.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fst_d */
{ "ldx.b", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_b */
{ "ldx.h", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_h */
{ "ldx.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_w */
{ "ldx.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_d */
{ "stx.b", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stx_b */
{ "stx.h", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stx_h */
{ "stx.w", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stx_w */
{ "stx.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stx_d */
{ "ldx.bu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_bu */
{ "ldx.hu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_hu */
{ "ldx.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldx_wu */
{ "fldx.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldx_s */
{ "fldx.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldx_d */
{ "fstx.s", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstx_s */
{ "fstx.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstx_d */
{ "amswap.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amswap_w */
{ "amswap.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amswap_d */
{ "amadd.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amadd_w */
{ "amadd.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amadd_d */
{ "amand.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amand_w */
{ "amand.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amand_d */
{ "amor.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amor_w */
{ "amor.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amor_d */
{ "amxor.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amxor_w */
{ "amxor.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amxor_d */
{ "ammax.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_w */
{ "ammax.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_d */
{ "ammin.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_w */
{ "ammin.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_d */
{ "ammax.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_wu */
{ "ammax.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_du */
{ "ammin.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_wu */
{ "ammin.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_du */
{ "amswap.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amswap_db_w */
{ "amswap.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amswap_db_d */
{ "amadd.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amadd_db_w */
{ "amadd.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amadd_db_d */
{ "amand.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amand_db_w */
{ "amand.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amand_db_d */
{ "amor.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amor_db_w */
{ "amor.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amor_db_d */
{ "amxor.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amxor_db_w */
{ "amxor.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_amxor_db_d */
{ "ammax.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_db_w */
{ "ammax.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_db_d */
{ "ammin.db.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_db_w */
{ "ammin.db.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_db_d */
{ "ammax.db.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_db_wu */
{ "ammax.db.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammax_db_du */
{ "ammin.db.wu", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_db_wu */
{ "ammin.db.du", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ammin_db_du */
{ "dbar", 0 }, /* Loong_dbar */
{ "ibar", 0 }, /* Loong_ibar */
{ "fldgt.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldgt_s */
{ "fldgt.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldgt_d */
{ "fldle.s", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldle_s */
{ "fldle.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_fldle_d */
{ "fstgt.s", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstgt_s */
{ "fstgt.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstgt_d */
{ "fstle.s", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstle_s */
{ "fstle.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_fstle_d */
{ "ldgt.b", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldgt_b */
{ "ldgt.h", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldgt_h */
{ "ldgt.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldgt_w */
{ "ldgt.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldgt_d */
{ "ldle.b", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldle_b */
{ "ldle.h", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldle_h */
{ "ldle.w", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldle_w */
{ "ldle.d", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_ldle_d */
{ "stgt.b", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stgt_b */
{ "stgt.h", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stgt_h */
{ "stgt.w", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stgt_w */
{ "stgt.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stgt_d */
{ "stle.b", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stle_b */
{ "stle.h", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stle_h */
{ "stle.w", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stle_w */
{ "stle.d", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_stle_d */
{ "beqz", CF_USE1 | CF_USE2 }, /* Loong_beqz */
{ "bnez", CF_USE1 | CF_USE2 }, /* Loong_bnez */
{ "bceqz", CF_USE1 | CF_USE2 }, /* Loong_bceqz */
{ "bcnez", CF_USE1 | CF_USE2 }, /* Loong_bcnez */
{ "jirl", CF_STOP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_CALL }, /* Loong_jirl */
{ "b", CF_STOP | CF_JUMP | CF_USE1 }, /* Loong_b */
{ "bl", CF_CALL | CF_USE1 }, /* Loong_bl */
{ "beq", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_beq */
{ "bne", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_bne */
{ "blt", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_blt */
{ "bge", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_bge */
{ "bltu", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_bltu */
{ "bgeu", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_bgeu */
{ "csrrd", CF_CHG1 | CF_USE2 }, /* Loong_csrrd */
{ "csrwr", CF_CHG1 | CF_USE2 }, /* Loong_csrwr */
{ "csrxchg", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_csrxchg */
{ "iocsrrd.b", CF_CHG1 | CF_USE2 }, /* Loong_iocsrrd_b */
{ "iocsrrd.h", CF_CHG1 | CF_USE2 }, /* Loong_iocsrrd_h */
{ "iocsrrd.w", CF_CHG1 | CF_USE2 }, /* Loong_iocsrrd_w */
{ "iocsrrd.d", CF_CHG1 | CF_USE2 }, /* Loong_iocsrrd_d */
{ "iocsrwr.b", CF_CHG1 | CF_USE2 }, /* Loong_iocsrwr_b */
{ "iocsrwr.h", CF_CHG1 | CF_USE2 }, /* Loong_iocsrwr_h */
{ "iocsrwr.w", CF_CHG1 | CF_USE2 }, /* Loong_iocsrwr_w */
{ "iocsrwr.d", CF_CHG1 | CF_USE2 }, /* Loong_iocsrwr_d */
{ "tlbsrch", 0 }, /* Loong_tlbsrch */
{ "tlbrd", 0 }, /* Loong_tlbrd */
{ "tlbwr", 0 }, /* Loong_tlbwr */
{ "tlbfill", 0 }, /* Loong_tlbfill */
{ "tlbclr", 0 }, /* Loong_tlbclr */
{ "tlbflush", 0 }, /* Loong_tlbflush */
{ "invtlb", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_invtlb */
{ "cacop", CF_USE1 | CF_USE2 | CF_USE3 }, /* Loong_cacop */
{ "lddir", CF_CHG1 | CF_USE2 | CF_USE3 }, /* Loong_lddir */
{ "ldpte", CF_USE1 | CF_USE2 }, /* Loong_ldpte */
{ "ertn", CF_STOP }, /* Loong_ertn */
{ "idle", 0 }, /* Loong_idle */
{ "dbcl", 0 }, /* Loong_dbcl */
 // fcmp.cond.suffix
{ "fcmp.caf.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_caf_s
{ "fcmp.saf.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_saf_s
{ "fcmp.clt.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_clt_s
{ "fcmp.slt.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_slt_s
{ "fcmp.ceq.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_ceq_s
{ "fcmp.seq.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_seq_s
{ "fcmp.cle.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cle_s
{ "fcmp.sle.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sle_s
{ "fcmp.cun.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cun_s
{ "fcmp.sun.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sun_s
{ "fcmp.cult.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cult_s
{ "fcmp.sult.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sult_s
{ "fcmp.cueq.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cueq_s
{ "fcmp.sueq.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sueq_s
{ "fcmp.cule.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cule_s
{ "fcmp.sule.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sule_s
{ "fcmp.cne.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cne_s
{ "fcmp.sne.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sne_s
{ "fcmp.cor.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cor_s
{ "fcmp.sor.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sor_s
{ "fcmp.cune.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cune_s
{ "fcmp.sune.s", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sune_s
 // and for .d
{ "fcmp.caf.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_caf_d
{ "fcmp.saf.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_saf_d
{ "fcmp.clt.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_clt_d
{ "fcmp.slt.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_slt_d
{ "fcmp.ceq.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_ceq_d
{ "fcmp.seq.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_seq_d
{ "fcmp.cle.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cle_d
{ "fcmp.sle.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sle_d
{ "fcmp.cun.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cun_d
{ "fcmp.sun.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sun_d
{ "fcmp.cult.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cult_d
{ "fcmp.sult.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sult_d
{ "fcmp.cueq.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cueq_d
{ "fcmp.sueq.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sueq_d
{ "fcmp.cule.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cule_d
{ "fcmp.sule.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sule_d
{ "fcmp.cne.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cne_d
{ "fcmp.sne.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sne_d
{ "fcmp.cor.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cor_d
{ "fcmp.sor.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sor_d
{ "fcmp.cune.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_cune_d
{ "fcmp.sune.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_fcmp_sune_d
 // LDL/LDR/STL/STR
{ "ldl.w", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_ldl_w
{ "ldl.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_ldl_d
{ "ldr.w", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_ldr_w
{ "ldr.d", CF_CHG1 | CF_USE2 | CF_USE3 }, // Loong_ldr_d
{ "stl.w", CF_USE1 | CF_USE2 | CF_USE3 }, // Loong_stl_w
{ "stl.d", CF_USE1 | CF_USE2 | CF_USE3 }, // Loong_stl_d
{ "str.w", CF_USE1 | CF_USE2 | CF_USE3 }, // Loong_str_w
{ "str.d", CF_USE1 | CF_USE2 | CF_USE3 }, // Loong_str_d
// pseudo ops
{ "mov", CF_CHG1 | CF_USE2 }, // Loong_mov 
{ "nop", 0 }, // Loong_nop 
};
