/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DECOMPRESS_UNLZMA_H
#define DECOMPRESS_UNLZMA_H

#ifdef __cplusplus
extern "C" {
#endif

int unlzma(unsigned char *, long,
	   long (*fill)(void*, unsigned long),
	   long (*flush)(void*, unsigned long),
	   unsigned char *output,
	   long *posp,
	   void(*error)(char *x)
	);

int __decompress(unsigned char *, long,
	   long (*fill)(void*, unsigned long),
	   long (*flush)(void*, unsigned long),
	   unsigned char *output,
	   long *posp,
	   void(*error)(char *x)
	);

#ifdef __cplusplus
};
#endif

#endif
