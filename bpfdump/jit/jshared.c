#include "types.h"
#include "bpf.h"
#include <stdlib.h>

#define PAGE_SIZE 	0x1000
#define MAX_ERRNO	4095

#define U16_MAX		((u16)~0U)
#define S16_MAX		((s16)(U16_MAX >> 1))
#define S16_MIN		((s16)(-S16_MAX - 1))
#define U32_MAX		((u32)~0U)
#define S32_MAX		((s32)(U32_MAX >> 1))
#define S32_MIN		((s32)(-S32_MAX - 1))

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })


#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

bool IS_ERR(const void *ptr)
{
  return (unsigned long)(ptr) >= (unsigned long)-MAX_ERRNO;
}

static inline void *ERR_PTR(long error)
{
  return (void *) error;
}

int bpf_jit_enable = 1;
u64 __bpf_call_base = 0;
void *__bpf_prog_enter = 0;
void *__bpf_prog_exit = 0;

void put_call_base(u64 addr, u64 enter, u64 ex)
{
  __bpf_call_base = addr;
  __bpf_prog_enter = (void *)enter;
  __bpf_prog_exit = (void *)ex;
}


void *kzalloc(size_t size, int flags)
{
  void *res = malloc(size);
  if ( res )
    memset(res, 0, size);
  return res;
}

void kfree(void *ptr)
{
  free(ptr);
}

void *kcalloc(size_t n, size_t size, int flags)
{
  return calloc(n, size);
}

void *kmalloc_array(size_t n, size_t size, int flags)
{
  return malloc(n * size);
}

void *kvcalloc(size_t n, size_t size, int flags)
{
  return calloc(n, size);
}

void kvfree(void *addr)
{
  free(addr);
}

static inline bool bpf_pseudo_func(const struct bpf_insn *insn)
{
	return insn->code == (BPF_LD | BPF_IMM | BPF_DW) &&
	       insn->src_reg == BPF_PSEUDO_FUNC;
}

void __bpf_prog_free(struct bpf_prog *fp)
{
	if (fp->aux) {
		free(fp->aux->poke_tab);
		free(fp->aux);
	}
	free(fp);
}

void bpf_prog_unlock_free(struct bpf_prog *fp)
{
 __bpf_prog_free(fp);
}

static void bpf_prog_clone_free(struct bpf_prog *fp)
{
	/* aux was stolen by the other clone, so we cannot free
	 * it from this path! It will be freed eventually by the
	 * other program on release.
	 *
	 * At this point, we don't need a deferred release since
	 * clone is guaranteed to not be locked.
	 */
	fp->aux = NULL;
	__bpf_prog_free(fp);
}

struct bpf_prog *bpf_prog_realloc(struct bpf_prog *fp_old, unsigned int size)
{
	struct bpf_prog *fp;
	u32 pages;

	size = round_up(size, PAGE_SIZE);
	pages = size / PAGE_SIZE;
	if (pages <= fp_old->pages)
		return fp_old;

	fp = malloc(size);
	if (fp) {
		memcpy(fp, fp_old, fp_old->pages * PAGE_SIZE);
		fp->pages = pages;
		fp->aux->prog = fp;

		/* We keep fp->aux from fp_old around in the new
		 * reallocated structure.
		 */
		fp_old->aux = NULL;
		__bpf_prog_free(fp_old);
	}

	return fp;
}

void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other)
{
	/* We have to repoint aux->prog to self, as we don't
	 * know whether fp here is the clone or the original.
	 */
	fp->aux->prog = fp;
	bpf_prog_clone_free(fp_other);
}

static struct bpf_prog *bpf_prog_clone_create(struct bpf_prog *fp_other)
{
	struct bpf_prog *fp;

	fp = malloc(fp_other->pages * PAGE_SIZE);
	if (fp != NULL) {
		/* aux->prog still points to the fp_other one, so
		 * when promoting the clone to the real program,
		 * this still needs to be adapted.
		 */
		memcpy(fp, fp_other, fp_other->pages * PAGE_SIZE);
	}

	return fp;
}

static int bpf_adj_delta_to_off(struct bpf_insn *insn, u32 pos, s32 end_old,
				s32 end_new, s32 curr, const bool probe_pass)
{
	const s32 off_min = S16_MIN, off_max = S16_MAX;
	s32 delta = end_new - end_old;
	s32 off = insn->off;

	if (curr < pos && curr + off + 1 >= end_old)
		off += delta;
	else if (curr >= end_new && curr + off + 1 < end_new)
		off -= delta;
	if (off < off_min || off > off_max)
		return -ERANGE;
	if (!probe_pass)
		insn->off = off;
	return 0;
}

static int bpf_adj_delta_to_imm(struct bpf_insn *insn, u32 pos, s32 end_old,
				s32 end_new, s32 curr, const bool probe_pass)
{
	const s64 imm_min = S32_MIN, imm_max = S32_MAX;
	s32 delta = end_new - end_old;
	s64 imm = insn->imm;

	if (curr < pos && curr + imm + 1 >= end_old)
		imm += delta;
	else if (curr >= end_new && curr + imm + 1 < end_new)
		imm -= delta;
	if (imm < imm_min || imm > imm_max)
		return -ERANGE;
	if (!probe_pass)
		insn->imm = imm;
	return 0;
}

static int bpf_adj_branches(struct bpf_prog *prog, u32 pos, s32 end_old,
			    s32 end_new, const bool probe_pass)
{
	u32 i, insn_cnt = prog->len + (probe_pass ? end_new - end_old : 0);
	struct bpf_insn *insn = prog->insnsi;
	int ret = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		u8 code;

		/* In the probing pass we still operate on the original,
		 * unpatched image in order to check overflows before we
		 * do any other adjustments. Therefore skip the patchlet.
		 */
		if (probe_pass && i == pos) {
			i = end_new;
			insn = prog->insnsi + end_old;
		}
		if (bpf_pseudo_func(insn)) {
			ret = bpf_adj_delta_to_imm(insn, pos, end_old,
						   end_new, i, probe_pass);
			if (ret)
				return ret;
			continue;
		}
		code = insn->code;
		if ((BPF_CLASS(code) != BPF_JMP &&
		     BPF_CLASS(code) != BPF_JMP32) ||
		    BPF_OP(code) == BPF_EXIT)
			continue;
		/* Adjust offset of jmps if we cross patch boundaries. */
		if (BPF_OP(code) == BPF_CALL) {
			if (insn->src_reg != BPF_PSEUDO_CALL)
				continue;
			ret = bpf_adj_delta_to_imm(insn, pos, end_old,
						   end_new, i, probe_pass);
		} else {
			ret = bpf_adj_delta_to_off(insn, pos, end_old,
						   end_new, i, probe_pass);
		}
		if (ret)
			break;
	}

	return ret;
}

static void bpf_adj_linfo(struct bpf_prog *prog, u32 off, u32 delta)
{
	struct bpf_line_info *linfo;
	u32 i, nr_linfo;

	nr_linfo = prog->aux->nr_linfo;
	if (!nr_linfo || !delta)
		return;

	linfo = prog->aux->linfo;

	for (i = 0; i < nr_linfo; i++)
		if (off < linfo[i].insn_off)
			break;

	/* Push all off < linfo[i].insn_off by delta */
	for (; i < nr_linfo; i++)
		linfo[i].insn_off += delta;
}

static inline unsigned int bpf_prog_size(unsigned int proglen)
{
	return max(sizeof(struct bpf_prog),
		   offsetof(struct bpf_prog, insnsi[proglen]));
}

struct bpf_prog *bpf_patch_insn_single(struct bpf_prog *prog, u32 off,
				       const struct bpf_insn *patch, u32 len)
{
	u32 insn_adj_cnt, insn_rest, insn_delta = len - 1;
	const u32 cnt_max = S16_MAX;
	struct bpf_prog *prog_adj;
	int err;

	/* Since our patchlet doesn't expand the image, we're done. */
	if (insn_delta == 0) {
		memcpy(prog->insnsi + off, patch, sizeof(*patch));
		return prog;
	}

	insn_adj_cnt = prog->len + insn_delta;

	/* Reject anything that would potentially let the insn->off
	 * target overflow when we have excessive program expansions.
	 * We need to probe here before we do any reallocation where
	 * we afterwards may not fail anymore.
	 */
	if (insn_adj_cnt > cnt_max &&
	    (err = bpf_adj_branches(prog, off, off + 1, off + len, true)))
		return ERR_PTR(err);

	/* Several new instructions need to be inserted. Make room
	 * for them. Likely, there's no need for a new allocation as
	 * last page could have large enough tailroom.
	 */
	prog_adj = bpf_prog_realloc(prog, bpf_prog_size(insn_adj_cnt));
	if (!prog_adj)
		return ERR_PTR(-ENOMEM);

	prog_adj->len = insn_adj_cnt;

	/* Patching happens in 3 steps:
	 *
	 * 1) Move over tail of insnsi from next instruction onwards,
	 *    so we can patch the single target insn with one or more
	 *    new ones (patching is always from 1 to n insns, n > 0).
	 * 2) Inject new instructions at the target location.
	 * 3) Adjust branch offsets if necessary.
	 */
	insn_rest = insn_adj_cnt - off - len;

	memmove(prog_adj->insnsi + off + len, prog_adj->insnsi + off + 1,
		sizeof(*patch) * insn_rest);
	memcpy(prog_adj->insnsi + off, patch, sizeof(*patch) * len);

	/* We are guaranteed to not fail at this point, otherwise
	 * the ship has sailed to reverse to the original state. An
	 * overflow cannot happen at this point.
	 */
//	BUG_ON(bpf_adj_branches(prog_adj, off, off + 1, off + len, false));

	bpf_adj_linfo(prog_adj, off, insn_delta);

	return prog_adj;
}

static int bpf_jit_blind_insn(const struct bpf_insn *from,
			      const struct bpf_insn *aux,
			      struct bpf_insn *to_buff,
			      bool emit_zext)
{
	struct bpf_insn *to = to_buff;
	u32 imm_rnd = rand();
	s16 off;

//	BUILD_BUG_ON(BPF_REG_AX  + 1 != MAX_BPF_JIT_REG);
//	BUILD_BUG_ON(MAX_BPF_REG + 1 != MAX_BPF_JIT_REG);

	/* Constraints on AX register:
	 *
	 * AX register is inaccessible from user space. It is mapped in
	 * all JITs, and used here for constant blinding rewrites. It is
	 * typically "stateless" meaning its contents are only valid within
	 * the executed instruction, but not across several instructions.
	 * There are a few exceptions however which are further detailed
	 * below.
	 *
	 * Constant blinding is only used by JITs, not in the interpreter.
	 * The interpreter uses AX in some occasions as a local temporary
	 * register e.g. in DIV or MOD instructions.
	 *
	 * In restricted circumstances, the verifier can also use the AX
	 * register for rewrites as long as they do not interfere with
	 * the above cases!
	 */
	if (from->dst_reg == BPF_REG_AX || from->src_reg == BPF_REG_AX)
		goto out;

	if (from->imm == 0 &&
	    (from->code == (BPF_ALU   | BPF_MOV | BPF_K) ||
	     from->code == (BPF_ALU64 | BPF_MOV | BPF_K))) {
		*to++ = BPF_ALU64_REG(BPF_XOR, from->dst_reg, from->dst_reg);
		goto out;
	}

	switch (from->code) {
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_OR  | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_K:
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU32_REG(from->code, from->dst_reg, BPF_REG_AX);
		break;

	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_OR  | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU64_REG(from->code, from->dst_reg, BPF_REG_AX);
		break;

	case BPF_JMP | BPF_JEQ  | BPF_K:
	case BPF_JMP | BPF_JNE  | BPF_K:
	case BPF_JMP | BPF_JGT  | BPF_K:
	case BPF_JMP | BPF_JLT  | BPF_K:
	case BPF_JMP | BPF_JGE  | BPF_K:
	case BPF_JMP | BPF_JLE  | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
		/* Accommodate for extra offset in case of a backjump. */
		off = from->off;
		if (off < 0)
			off -= 2;
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_JMP_REG(from->code, from->dst_reg, BPF_REG_AX, off);
		break;

	case BPF_JMP32 | BPF_JEQ  | BPF_K:
	case BPF_JMP32 | BPF_JNE  | BPF_K:
	case BPF_JMP32 | BPF_JGT  | BPF_K:
	case BPF_JMP32 | BPF_JLT  | BPF_K:
	case BPF_JMP32 | BPF_JGE  | BPF_K:
	case BPF_JMP32 | BPF_JLE  | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
		/* Accommodate for extra offset in case of a backjump. */
		off = from->off;
		if (off < 0)
			off -= 2;
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_JMP32_REG(from->code, from->dst_reg, BPF_REG_AX,
				      off);
		break;

	case BPF_LD | BPF_IMM | BPF_DW:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[1].imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
		*to++ = BPF_ALU64_REG(BPF_MOV, aux[0].dst_reg, BPF_REG_AX);
		break;
	case 0: /* Part 2 of BPF_LD | BPF_IMM | BPF_DW. */
		*to++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ aux[0].imm);
		*to++ = BPF_ALU32_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		if (emit_zext)
			*to++ = BPF_ZEXT_REG(BPF_REG_AX);
		*to++ = BPF_ALU64_REG(BPF_OR,  aux[0].dst_reg, BPF_REG_AX);
		break;

	case BPF_ST | BPF_MEM | BPF_DW:
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
		*to++ = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, imm_rnd ^ from->imm);
		*to++ = BPF_ALU64_IMM(BPF_XOR, BPF_REG_AX, imm_rnd);
		*to++ = BPF_STX_MEM(from->code, from->dst_reg, BPF_REG_AX, from->off);
		break;
	}
out:
	return to - to_buff;
}

struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *prog)
{
	struct bpf_insn insn_buff[16], aux[2];
	struct bpf_prog *clone, *tmp;
	int insn_delta, insn_cnt;
	struct bpf_insn *insn;
	int i, rewritten;

	if (!prog->blinding_requested || prog->blinded)
		return prog;

	clone = bpf_prog_clone_create(prog);
	if (!clone)
		return ERR_PTR(-ENOMEM);

	insn_cnt = clone->len;
	insn = clone->insnsi;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			/* ld_imm64 with an address of bpf subprog is not
			 * a user controlled constant. Don't randomize it,
			 * since it will conflict with jit_subprogs() logic.
			 */
			insn++;
			i++;
			continue;
		}

		/* We temporarily need to hold the original ld64 insn
		 * so that we can still access the first part in the
		 * second blinding run.
		 */
		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW) &&
		    insn[1].code == 0)
			memcpy(aux, insn, sizeof(aux));

		rewritten = bpf_jit_blind_insn(insn, aux, insn_buff,
						clone->aux->verifier_zext);
		if (!rewritten)
			continue;

		tmp = bpf_patch_insn_single(clone, i, insn_buff, rewritten);
		if (IS_ERR(tmp)) {
			/* Patching may have repointed aux->prog during
			 * realloc from the original one, so we need to
			 * fix it up here on error.
			 */
			bpf_jit_prog_release_other(prog, clone);
			return tmp;
		}

		clone = tmp;
		insn_delta = rewritten - 1;

		/* Walk new program and skip insns we just inserted. */
		insn = clone->insnsi + i + insn_delta;
		insn_cnt += insn_delta;
		i        += insn_delta;
	}

	clone->blinded = 1;
	return clone;
}

void bpf_prog_fill_jited_linfo(struct bpf_prog *prog,
			       const u32 *insn_to_jit_off)
{
	u32 linfo_idx, insn_start, insn_end, nr_linfo, i;
	const struct bpf_line_info *linfo;
	void **jited_linfo;

	if (!prog->aux->jited_linfo)
		/* Userspace did not provide linfo */
		return;

	linfo_idx = prog->aux->linfo_idx;
	linfo = &prog->aux->linfo[linfo_idx];
	insn_start = linfo[0].insn_off;
	insn_end = insn_start + prog->len;

	jited_linfo = &prog->aux->jited_linfo[linfo_idx];
	jited_linfo[0] = prog->bpf_func;

	nr_linfo = prog->aux->nr_linfo - linfo_idx;

	for (i = 1; i < nr_linfo && linfo[i].insn_off < insn_end; i++)
		/* The verifier ensures that linfo[i].insn_off is
		 * strictly increasing
		 */
		jited_linfo[i] = prog->bpf_func +
			insn_to_jit_off[linfo[i].insn_off - insn_start - 1];
}

int bpf_jit_get_func_addr(const struct bpf_prog *prog,
			  const struct bpf_insn *insn, bool extra_pass,
			  u64 *func_addr, bool *func_addr_fixed)
{
	s16 off = insn->off;
	s32 imm = insn->imm;
	u8 *addr;

	*func_addr_fixed = insn->src_reg != BPF_PSEUDO_CALL;
	if (!*func_addr_fixed) {
		/* Place-holder address till the last pass has collected
		 * all addresses for JITed subprograms in which case we
		 * can pick them up from prog->aux.
		 */
		if (!extra_pass)
			addr = NULL;
		else if (prog->aux->func &&
			 off >= 0 && off < prog->aux->func_cnt)
			addr = (u8 *)prog->aux->func[off]->bpf_func;
		else
			return -EINVAL;
	} else {
		/* Address of a BPF helper call. Since part of the core
		 * kernel, it's always at a fixed location. __bpf_call_base
		 * and the helper with imm relative to it are both in core
		 * kernel.
		 */
		addr = (u8 *)__bpf_call_base + imm;
	}

	*func_addr = (unsigned long)addr;
	return 0;
}
void flush_icache_range(unsigned long start, unsigned long end)
{
}

const char hexes[] = "0123456789ABCDEF";

void HexDump(unsigned char *From, int Len)
{
 int i;
 int j,k;
 char buffer[256];
 char *ptr;

 for(i=0;i<Len;)
     {
          ptr = buffer;
          sprintf(ptr, "%08X ",i);
          ptr += 9;
          for(j=0;j<16 && i<Len;j++,i++)
          {
             *ptr++ = j && !(j%4)?(!(j%8)?'|':'-'):' ';
             *ptr++ = hexes[From[i] >> 4];
             *ptr++ = hexes[From[i] & 0xF];
          }
          for(k=16-j;k!=0;k--)
          {
            ptr[0] = ptr[1] = ptr[2] = ' ';
            ptr += 3;

          }
          ptr[0] = ptr[1] = ' ';
          ptr += 2;
          for(;j!=0;j--)
          {
               if(From[i-j]>=0x20)
                    *ptr = From[i-j];
               else
                    *ptr = '.';
               ptr++;
          }
          *ptr = 0;
          printf("%s\n", buffer);
     }
     printf("\n");
}

void bpf_jit_dump(unsigned int flen, unsigned int proglen, u32 pass, void *image)
{
  printf("flen=%u proglen=%u pass=%u\n", flen, proglen, pass);
  HexDump(image, proglen);
}

void print_fn_code(unsigned char *code, unsigned long len)
{
}

void cond_resched()
{
}

void bpf_jit_binary_lock_ro(struct bpf_binary_header *hdr)
{
}

bool is_bpf_text_address(unsigned long addr)
{
  printf("is_bpf_text_address(%lX)\n", addr);
  return false;
}

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns)
{
  struct bpf_binary_header *hdr;
  u32 size, hole, start = 0;
  size = round_up(proglen + sizeof(*hdr) + 128, PAGE_SIZE);
  hdr = malloc(size);
printf("bpf_jit_binary_alloc(%X) %p\n", size, hdr); fflush(stdout);
  if ( !hdr )
    return NULL;
  hdr->size = size;
  hole = min(size - (proglen + sizeof(*hdr)), PAGE_SIZE - sizeof(*hdr));

  /* Leave a random number of instructions before BPF code. */
  *image_ptr = &hdr->image[start];
  return hdr;  
}

void bpf_jit_binary_free(struct bpf_binary_header *hdr)
{
  free(hdr);
}

int is_kernel_text(unsigned long addr)
{
  return 0;
}

void smp_wmb()
{
}

void __set_bit(unsigned int nr, volatile unsigned long *addr)
{
  *addr |= (1UL << nr);
}

int test_bit(int nr, const volatile unsigned long *addr)
{
  if ( (1UL << nr) & *addr )
    return 1;
   return 0;
}

unsigned long __ffs(unsigned long word)
{
	int num = 0;

#if __BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}
