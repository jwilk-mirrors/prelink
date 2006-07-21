/* Copyright (C) 2001, 2002, 2004 Red Hat, Inc.
   Written by Jakub Jelinek <jakub@redhat.com>, 2001.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>

#include "prelink.h"

#define SPARC64_R_TYPE(info) (GELF_R_TYPE (info) & 0xff)

static int
sparc64_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int i;

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			      dso->shdr[i].sh_name), ".got"))
	  {
	    Elf64_Addr data;

	    data = read_ube64 (dso, dso->shdr[i].sh_addr);
	    /* .got[0] points to _DYNAMIC, it needs to be adjusted.  */
	    if (data == dso->shdr[n].sh_addr && data >= start)
	      write_be64 (dso, dso->shdr[i].sh_addr, data + adjust);
	    break;
	  }
    }

  return 0;
}

static int
sparc64_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  error (0, 0, "%s: Sparc doesn't support REL relocs", dso->filename);
  return 1;
}

static int
sparc64_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  if (SPARC64_R_TYPE (rela->r_info) == R_SPARC_RELATIVE)
    {
      if (rela->r_addend >= start)
	rela->r_addend += adjust;
    }
  else if (SPARC64_R_TYPE (rela->r_info) == R_SPARC_JMP_SLOT
	   && rela->r_addend)
    {
      /* .plt[32768+] r_addends are -some_address_in_plt_section.  */
      if ((- rela->r_addend) >= start)
	rela->r_addend -= adjust;
    }
  return 0;
}

static int
sparc64_prelink_rel (struct prelink_info *info, GElf_Rel *rel,
		   GElf_Addr reladdr)
{
  error (0, 0, "%s: Sparc doesn't support REL relocs", info->dso->filename);
  return 1;
}

static void
sparc64_fixup_plt (DSO *dso, GElf_Rela *rela, GElf_Addr value)
{
  Elf64_Sxword disp = value - rela->r_offset;

  if (rela->r_addend)
    {
      /* .plt[32768+]  */
      write_be64 (dso, rela->r_offset, value);
    }
  else if (disp >= -0x800000 && disp < 0x800000)
    {
      /* b,a value
	  nop
	 nop  */
      write_be32 (dso, rela->r_offset, 0x30800000 | ((disp >> 2) & 0x3fffff));
      write_be32 (dso, rela->r_offset + 4, 0x01000000);
      write_be32 (dso, rela->r_offset + 8, 0x01000000);
    }
  else if (! (value >> 32))
    {
      /* sethi %hi(value), %g1
	 jmpl %g1 + %lo(value), %g0
	  nop  */
      write_be32 (dso, rela->r_offset, 0x03000000 | ((value >> 10) & 0x3fffff));
      write_be32 (dso, rela->r_offset + 4, 0x81c06000 | (value & 0x3ff));
      write_be32 (dso, rela->r_offset + 8, 0x01000000);
    }
  else if ((rela->r_offset + 4 > value
	    && ((rela->r_offset - value) >> 31) == 0)
	   || (value > rela->r_offset + 4
	       && ((value - rela->r_offset - 4) >> 31) == 0))
    {
      /* mov %o7, %g1
	 call value
	  mov %g1, %o7  */
      write_be32 (dso, rela->r_offset, 0x8210000f);
      write_be32 (dso, rela->r_offset + 4, 0x40000000
		  | (((value - rela->r_offset - 4) >> 2) & 0x3fffffff));
      write_be32 (dso, rela->r_offset + 8, 0x9e100001);
    }
  else
    {
      unsigned int csts[4];
      int i = 0;

      /* sethi %hh(value), %g1
	 sethi %lm(value), %g5
	 or %g1, %hm(value), %g1
	 or %g5, %lo(value), %g5
	 sllx %g1, 32, %g1
	 jmpl %g1 + %g5, %g0
	  nop  */

      csts[0] = value >> 42;
      csts[1] = (value >> 32) & 0x3ff;
      csts[2] = (value >> 10) & 0x3fffff;
      csts[3] = value & 0x3ff;
      write_be32 (dso, rela->r_offset, 0x03000000 | csts[0]);
      write_be32 (dso, rela->r_offset + 4, 0x0b000000 | csts[2]);
      /* Sparc64 shared libs are often 0xfffff800XXXXXXXX, so optimize
	 for this common case.  */
      if (csts[1] == 0)
	write_be32 (dso, rela->r_offset + 8, 0x83287020);
      else
	write_be32 (dso, rela->r_offset + 8, 0x82106000 | csts[1]);
      write_be32 (dso, rela->r_offset + 12, 0x8a116000 | csts[3]);
      if (csts[1] != 0)
	write_be32 (dso, rela->r_offset + 16, 0x83287020), i = 4;
      write_be32 (dso, rela->r_offset + 16 + i, 0x81c04005);
      write_be32 (dso, rela->r_offset + 20 + i, 0x01000000);
    }
}

static int
sparc64_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		    GElf_Addr relaaddr)
{
  DSO *dso = info->dso;
  GElf_Addr value;

  if (SPARC64_R_TYPE (rela->r_info) == R_SPARC_NONE)
    return 0;
  else if (SPARC64_R_TYPE (rela->r_info) == R_SPARC_RELATIVE)
    {
      /* 64-bit SPARC handles RELATIVE relocs as
	 *(long *)rela->r_offset = l_addr + rela->r_addend,
	 so we must update the memory.  */
      write_be64 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 SPARC64_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (SPARC64_R_TYPE (rela->r_info))
    {
    case R_SPARC_GLOB_DAT:
    case R_SPARC_64:
    case R_SPARC_UA64:
      write_be64 (dso, rela->r_offset, value);
      break;
    case R_SPARC_32:
    case R_SPARC_UA32:
      write_be32 (dso, rela->r_offset, value);
      break;
    case R_SPARC_JMP_SLOT:
      sparc64_fixup_plt (dso, rela, value);
      break;
    case R_SPARC_8:
      write_8 (dso, rela->r_offset, value);
      break;
    case R_SPARC_16:
    case R_SPARC_UA16:
      write_be16 (dso, rela->r_offset, value);
      break;
    case R_SPARC_LO10:
      write_be32 (dso, rela->r_offset,
		  (value & 0x3ff) | (read_ube32 (dso, rela->r_offset) & ~0x3ff));
      break;
    case R_SPARC_LM22:
    case R_SPARC_HI22:
      write_be32 (dso, rela->r_offset,
		  ((value >> 10) & 0x3fffff)
		  | (read_ube32 (dso, rela->r_offset) & 0xffc00000));
      break;
    case R_SPARC_DISP8:
      write_8 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_SPARC_DISP16:
      write_be16 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_SPARC_DISP32:
      write_be32 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_SPARC_DISP64:
      write_be64 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_SPARC_WDISP30:
      write_be32 (dso, rela->r_offset,
		  (((value - rela->r_offset) >> 2) & 0x3fffffff)
		  | (read_ube32 (dso, rela->r_offset) & 0xc0000000));
      break;
    case R_SPARC_H44:
      write_be32 (dso, rela->r_offset,
		  ((value >> 22) & 0x3fffff)
		  | (read_ube32 (dso, rela->r_offset) & 0xffc00000));
      break;
    case R_SPARC_M44:
      write_be32 (dso, rela->r_offset,
		  ((value >> 12) & 0x3ff)
		  | (read_ube32 (dso, rela->r_offset) & ~0x3ff));
      break;
    case R_SPARC_L44:
      write_be32 (dso, rela->r_offset,
		  (value & 0xfff) | (read_ube32 (dso, rela->r_offset) & ~0xfff));
      break;
    case R_SPARC_HH22:
      write_be32 (dso, rela->r_offset,
		  ((value >> 42) & 0x3fffff)
		  | (read_ube32 (dso, rela->r_offset) & 0xffc00000));
      break;
    case R_SPARC_HM10:
      write_be32 (dso, rela->r_offset,
		  ((value >> 32) & 0x3ff)
		  | (read_ube32 (dso, rela->r_offset) & ~0x3ff));
      break;
    case R_SPARC_OLO10:
      write_be32 (dso, rela->r_offset,
		  (((value & 0x3ff) + (GELF_R_TYPE (rela->r_info) >> 8)) & 0x1fff)
		  | (read_ube32 (dso, rela->r_offset) & ~0x1fff));
      break;
    case R_SPARC_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_SPARC_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown sparc relocation type %d", dso->filename,
	     (int) SPARC64_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
sparc64_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (SPARC64_R_TYPE (rela->r_info))
    {
    case R_SPARC_64:
    case R_SPARC_UA64:
      buf_write_be64 (buf, rela->r_addend);
      break;
    case R_SPARC_32:
    case R_SPARC_UA32:
      buf_write_be32 (buf, rela->r_addend);
      break;
    case R_SPARC_16:
    case R_SPARC_UA16:
      buf_write_be16 (buf, rela->r_addend);
      break;
    case R_SPARC_8:
      buf_write_8 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
sparc64_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: Sparc doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
sparc64_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 SPARC64_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (SPARC64_R_TYPE (rela->r_info))
    {
    case R_SPARC_NONE:
      break;
    case R_SPARC_DISP64:
      value -= rela->r_offset;
    case R_SPARC_GLOB_DAT:
    case R_SPARC_64:
    case R_SPARC_UA64:
      buf_write_be64 (buf, value);
      break;
    case R_SPARC_DISP32:
      value -= rela->r_offset;
    case R_SPARC_32:
    case R_SPARC_UA32:
      buf_write_be32 (buf, value);
      break;
    case R_SPARC_DISP16:
      value -= rela->r_offset;
    case R_SPARC_16:
    case R_SPARC_UA16:
      buf_write_be16 (buf, value);
      break;
    case R_SPARC_DISP8:
      value -= rela->r_offset;
    case R_SPARC_8:
      buf_write_8 (buf, value);
      break;
    case R_SPARC_LO10:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & ~0x3ff) | (value & 0x3ff));
      break;
    case R_SPARC_LM22:
    case R_SPARC_HI22:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & 0xffc00000)
			   | ((value >> 10) & 0x3fffff));
      break;
    case R_SPARC_WDISP30:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & 0xc0000000)
			   | (((value - rela->r_offset) >> 2) & 0x3fffffff));
      break;
    case R_SPARC_H44:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & 0xffc00000)
			   | ((value >> 22) & 0x3fffff));
      break;
    case R_SPARC_M44:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & ~0x3ff)
			   | ((value >> 12) & 0x3ff));
      break;
    case R_SPARC_L44:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & ~0xfff) | (value & 0xfff));
      break;
    case R_SPARC_HH22:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & 0xffc00000)
			   | ((value >> 42) & 0x3fffff));
      break;
    case R_SPARC_HM10:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & ~0x3ff)
			   | ((value >> 32) & 0x3ff));
      break;
    case R_SPARC_OLO10:
      buf_write_be32 (buf, (buf_read_ube32 (buf) & ~0x1fff)
			   | (((value & 0x3ff)
			       + (GELF_R_TYPE (rela->r_info) >> 8)) & 0x1fff));
      break;
    case R_SPARC_RELATIVE:
      error (0, 0, "%s: R_SPARC_RELATIVE in ET_EXEC object?",
	     info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
sparc64_prelink_conflict_rel (DSO *dso, struct prelink_info *info,
			    GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: Sparc doesn't support REL relocs", dso->filename);
  return 1;
}

static int
sparc64_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			     GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;
  int r_type;

  if (SPARC64_R_TYPE (rela->r_info) == R_SPARC_RELATIVE
      || SPARC64_R_TYPE (rela->r_info) == R_SPARC_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       SPARC64_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict_lookup_value (conflict);
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  value += rela->r_addend;
  r_type = SPARC64_R_TYPE (rela->r_info);
  switch (r_type)
    {
    case R_SPARC_DISP64:
      value -= rela->r_offset;
    case R_SPARC_GLOB_DAT:
    case R_SPARC_64:
      r_type = R_SPARC_64;
      break;
    case R_SPARC_DISP32:
      value -= rela->r_offset;
    case R_SPARC_32:
      r_type = R_SPARC_32;
      break;
    case R_SPARC_DISP16:
      value -= rela->r_offset;
    case R_SPARC_16:
      r_type = R_SPARC_16;
      break;
    case R_SPARC_DISP8:
      value -= rela->r_offset;
    case R_SPARC_8:
      r_type = R_SPARC_8;
      break;
    /* Attempt to transform all reloc which read-modify-write into
       simple writes.  */
    case R_SPARC_LO10:
      value = (read_ube32 (dso, rela->r_offset) & ~0x3ff) | (value & 0x3ff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_LM22:
    case R_SPARC_HI22:
      value = (read_ube32 (dso, rela->r_offset) & 0xffc00000)
	      | ((value >> 10) & 0x3fffff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_WDISP30:
      value = (read_ube32 (dso, rela->r_offset) & 0xc0000000)
	      | (((value - rela->r_offset) >> 2) & 0x3fffffff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_H44:
      value = (read_ube32 (dso, rela->r_offset) & 0xffc00000)
	      | ((value >> 22) & 0x3fffff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_M44:
      value = (read_ube32 (dso, rela->r_offset) & ~0x3ff)
	      | ((value >> 12) & 0x3ff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_L44:
      value = (read_ube32 (dso, rela->r_offset) & ~0xfff) | (value & 0xfff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_HH22:
      value = (read_ube32 (dso, rela->r_offset) & 0xffc00000)
	      | ((value >> 42) & 0x3fffff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_HM10:
      value = (read_ube32 (dso, rela->r_offset) & ~0x3ff)
	      | ((value >> 32) & 0x3ff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_OLO10:
      value = (read_ube32 (dso, rela->r_offset) & ~0x1fff)
	      | (((value & 0x3ff) + (GELF_R_TYPE (rela->r_info) >> 8)) & 0x1fff);
      r_type = R_SPARC_32;
      break;
    case R_SPARC_JMP_SLOT:
      if (rela->r_addend)
	r_type = R_SPARC_64;
      break;
    case R_SPARC_UA16:
    case R_SPARC_UA32:
    case R_SPARC_UA64:
      break;
    default:
      error (0, 0, "%s: Unknown Sparc relocation type %d", dso->filename,
	     r_type);
      return 1;
    }
  ret->r_info = GELF_R_INFO (0, r_type);
  ret->r_addend = value;
  return 0;
}

static int
sparc64_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: Sparc doesn't support REL relocs", dso->filename);
  return 1;
}

static int
sparc64_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
sparc64_arch_prelink (DSO *dso)
{
  return 0;
}

static int
sparc64_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  int sec;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SPARC_NONE:
      break;
    case R_SPARC_JMP_SLOT:
      sec = addr_to_sec (dso, rela->r_offset);
      if (sec != -1)
	{
	  if (rela->r_addend == 0)
	    {
	      /* sethi .-.plt, %g1
		 b,a %xcc, .plt+0x20  */
	      write_be32 (dso, rela->r_offset,
			  0x03000000
			  | ((rela->r_offset - dso->shdr[sec].sh_addr)
			     & 0x3fffff));
	      write_be32 (dso, rela->r_offset + 4,
			  0x30680000
			  | (((dso->shdr[sec].sh_addr + 32
			       - rela->r_offset - 4) >> 2)
			     & 0x7ffff));
	      write_be32 (dso, rela->r_offset + 8, 0x01000000);
	      write_be32 (dso, rela->r_offset + 12, 0x01000000);
	      write_be32 (dso, rela->r_offset + 16, 0x01000000);
	      write_be32 (dso, rela->r_offset + 20, 0x01000000);
	      write_be32 (dso, rela->r_offset + 24, 0x01000000);
	      write_be32 (dso, rela->r_offset + 28, 0x01000000);
	    }
	  else
	    {
	      GElf_Addr slot = ((rela->r_offset + 0x400
				 - dso->shdr[sec].sh_addr)
				/ 0x1400) * 0x1400
			       + dso->shdr[sec].sh_addr - 0x400;
	      /* slot+12 contains: ldx [%o7 + X], %g1  */
	      GElf_Addr ptr = slot + (read_ube32 (dso, slot + 12) & 0xfff) + 4;

	      write_be64 (dso, rela->r_offset,
			  dso->shdr[sec].sh_addr
			  - (slot + ((rela->r_offset - ptr) / 8) * 24 + 4));
	    }
	}
      break;
    case R_SPARC_RELATIVE:
    case R_SPARC_GLOB_DAT:
    case R_SPARC_64:
    case R_SPARC_UA64:
    case R_SPARC_DISP64:
      write_be64 (dso, rela->r_offset, 0);
      break;
    case R_SPARC_32:
    case R_SPARC_UA32:
    case R_SPARC_DISP32:
      write_be32 (dso, rela->r_offset, 0);
      break;
    case R_SPARC_8:
    case R_SPARC_DISP8:
      write_8 (dso, rela->r_offset, 0);
      break;
    case R_SPARC_16:
    case R_SPARC_UA16:
    case R_SPARC_DISP16:
      write_be16 (dso, rela->r_offset, 0);
      break;
    case R_SPARC_LO10:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & ~0x3ff);
      break;
    case R_SPARC_LM22:
    case R_SPARC_HI22:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffc00000);
      break;
    case R_SPARC_WDISP30:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xc0000000);
      break;
    case R_SPARC_H44:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffc00000);
      break;
    case R_SPARC_M44:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & ~0x3ff);
      break;
    case R_SPARC_L44:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & ~0xfff);
      break;
    case R_SPARC_HH22:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffc00000);
      break;
    case R_SPARC_HM10:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & ~0x3ff);
      break;
    case R_SPARC_OLO10:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & ~0x1fff);
      break;
    case R_SPARC_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_SPARC_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown sparc relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
sparc64_reloc_size (int reloc_type)
{
  switch (reloc_type)
    {
    case R_SPARC_8:
    case R_SPARC_DISP8:
      return 1;
    case R_SPARC_16:
    case R_SPARC_DISP16:
    case R_SPARC_UA16:
      return 2;
    case R_SPARC_RELATIVE:
    case R_SPARC_64:
    case R_SPARC_UA64:
    case R_SPARC_GLOB_DAT:
      return 8;
    default:
      break;
    }
  return 4;
}

static int
sparc64_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_SPARC_COPY: return RTYPE_CLASS_COPY;
    case R_SPARC_JMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "SPARC",
  .class = ELFCLASS64,
  .machine = EM_SPARCV9,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_SPARC_JMP_SLOT,
  .R_COPY = R_SPARC_COPY,
  .R_RELATIVE = R_SPARC_RELATIVE,
  .dynamic_linker = "/lib64/ld-linux.so.2",
  .adjust_dyn = sparc64_adjust_dyn,
  .adjust_rel = sparc64_adjust_rel,
  .adjust_rela = sparc64_adjust_rela,
  .prelink_rel = sparc64_prelink_rel,
  .prelink_rela = sparc64_prelink_rela,
  .prelink_conflict_rel = sparc64_prelink_conflict_rel,
  .prelink_conflict_rela = sparc64_prelink_conflict_rela,
  .apply_conflict_rela = sparc64_apply_conflict_rela,
  .apply_rel = sparc64_apply_rel,
  .apply_rela = sparc64_apply_rela,
  .rel_to_rela = sparc64_rel_to_rela,
  .need_rel_to_rela = sparc64_need_rel_to_rela,
  .reloc_size = sparc64_reloc_size,
  .reloc_class = sparc64_reloc_class,
  .max_reloc_size = 8,
  .arch_prelink = sparc64_arch_prelink,
  .undo_prelink_rela = sparc64_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0xfffff80000000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0xfffff80001000000LL,
  /* If we need yet more space for shared libraries, we can of course
     expand, but limiting all DSOs into 4 GB means stack overflows
     jumping to shared library functions is much harder (there is
     '\0' byte in the address before the bytes that matter).  */
  .mmap_end =  0xfffff80100000000LL,
  .max_page_size = 0x100000,
  .page_size = 0x2000
};
