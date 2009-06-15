/* Copyright (C) 2001, 2002, 2003, 2004, 2009 Red Hat, Inc.
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

static int
alpha_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		  GElf_Addr adjust)
{
  return 0;
}

static int
alpha_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		  GElf_Addr adjust)
{
  error (0, 0, "%s: Alpha doesn't support REL relocs", dso->filename);
  return 1;
}

static int
alpha_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		   GElf_Addr adjust)
{
  if (GELF_R_TYPE (rela->r_info) == R_ALPHA_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_ALPHA_JMP_SLOT)
    {
      GElf_Addr val = read_ule64 (dso, rela->r_offset);

      if (val >= start)
	{
	  write_le64 (dso, rela->r_offset, val + adjust);
	  if (val == rela->r_addend)
	    rela->r_addend += adjust;
	}
    }
  else if (GELF_R_TYPE (rela->r_info) == R_ALPHA_GLOB_DAT)
    {
      GElf_Addr val = read_ule64 (dso, rela->r_offset) - rela->r_addend;

      if (val && val >= start)
	write_le64 (dso, rela->r_offset, val + adjust + rela->r_addend);
    }
  return 0;
}

static int
alpha_prelink_rel (struct prelink_info *info, GElf_Rel *rel,
		   GElf_Addr reladdr)
{
  error (0, 0, "%s: Alpha doesn't support REL relocs", info->dso->filename);
  return 1;
}

static void
alpha_fixup_plt (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr,
		 GElf_Addr value)
{
  Elf64_Sxword disp;
  Elf64_Addr plt;

  relaaddr -= dso->info[DT_JMPREL];
  relaaddr /= sizeof (Elf64_Rela);
  relaaddr *= 12;
  plt = dso->info[DT_PLTGOT] + 32 + relaaddr;
  disp = ((Elf64_Sxword) (value - plt - 12)) / 4;
  if (disp >= -0x100000 && disp < 0x100000)
    {
      int32_t hi, lo;

      hi = value - plt;
      lo = (int16_t) hi;
      hi = (hi - lo) >> 16;

      /* ldah $27,hi($27)
	 lda $27,lo($27)
	 br $31,value  */
      write_le32 (dso, plt, 0x277b0000 | (hi & 0xffff));
      write_le32 (dso, plt + 4, 0x237b0000 | (lo & 0xffff));
      write_le32 (dso, plt + 8, 0xc3e00000 | (disp & 0x1fffff));
    }
  else
    {
      int32_t hi, lo;

      hi = rela->r_offset - plt;
      lo = (int16_t) hi;
      hi = (hi - lo) >> 16;

      /* ldah $27,hi($27)
	 ldq $27,lo($27)
	 jmp $31,($27)  */
      write_le32 (dso, plt, 0x277b0000 | (hi & 0xffff));
      write_le32 (dso, plt + 4, 0xa77b0000 | (lo & 0xffff));
      write_le32 (dso, plt + 8, 0x6bfb0000);
    }
}

static int
alpha_is_indirect_plt (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  Elf64_Addr pltaddr;
  uint32_t plt[3];
  int32_t hi, lo;

  relaaddr -= dso->info[DT_JMPREL];
  relaaddr /= sizeof (Elf64_Rela);
  relaaddr *= 12;
  pltaddr = dso->info[DT_PLTGOT] + 32 + relaaddr;
  hi = rela->r_offset - pltaddr;
  lo = (int16_t) hi;
  hi = (hi - lo) >> 16;
  plt[0] = read_ule32 (dso, pltaddr);
  plt[1] = read_ule32 (dso, pltaddr + 4);
  plt[2] = read_ule32 (dso, pltaddr + 8);
  if (plt[0] == (0x277b0000 | (hi & 0xffff))
      && plt[1] == (0xa77b0000 | (lo & 0xffff))
      && plt[2] == 0x6bfb0000)
    return 1;
  return 0;
}

static int
alpha_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		    GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_ALPHA_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_ALPHA_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ALPHA_GLOB_DAT:
    case R_ALPHA_REFQUAD:
    case R_ALPHA_DTPREL64:
      write_le64 (dso, rela->r_offset, value);
      break;
    case R_ALPHA_JMP_SLOT:
      write_le64 (dso, rela->r_offset, value);
      alpha_fixup_plt (dso, rela, relaaddr, value);
      break;
    /* DTPMOD64 and TPREL64 is impossible to predict in shared libraries
       unless prelink sets the rules.  */
    case R_ALPHA_DTPMOD64:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_ALPHA_DTPMOD64 reloc in executable?",
		 dso->filename);
	  return 1;
	}
      break;
    case R_ALPHA_TPREL64:
      if (dso->ehdr.e_type == ET_EXEC && info->resolvetls)
	write_le64 (dso, rela->r_offset, value + info->resolvetls->offset);
      break;
    default:
      error (0, 0, "%s: Unknown alpha relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
alpha_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			   char *buf, GElf_Addr dest_addr)
{
  switch (GELF_R_TYPE (rela->r_info) & 0xff)
    {
    case R_ALPHA_GLOB_DAT:
    case R_ALPHA_REFQUAD:
    case R_ALPHA_JMP_SLOT:
      buf_write_le64 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
alpha_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: Alpha doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
alpha_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ALPHA_NONE:
      break;
    case R_ALPHA_GLOB_DAT:
    case R_ALPHA_REFQUAD:
    case R_ALPHA_JMP_SLOT:
      buf_write_le64 (buf, value + rela->r_addend);
      break;
    case R_ALPHA_RELATIVE:
      error (0, 0, "%s: R_ALPHA_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
alpha_prelink_conflict_rel (DSO *dso, struct prelink_info *info,
			    GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: Alpha doesn't support REL relocs", dso->filename);
  return 1;
}

static int
alpha_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			     GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_ALPHA_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_ALPHA_NONE
      || info->dso == dso)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    {
      if (info->curtls == NULL)
	return 0;
      switch (GELF_R_TYPE (rela->r_info))
	{
	/* Even local DTPMOD64 and TPREL64 relocs need conflicts.  */
	case R_ALPHA_DTPMOD64:
	case R_ALPHA_TPREL64:
	  break;
	default:
	  return 0;
	}
      value = 0;
    }
  else if (conflict->ifunc)
    {
      error (0, 0, "%s: STT_GNU_IFUNC not handled on Alpha yet",
	     dso->filename);
      return 1;
    }
  else
    {
      /* DTPREL64 wants to see only real conflicts, not lookups
	 with reloc_class RTYPE_CLASS_TLS.  */
      if (GELF_R_TYPE (rela->r_info) == R_ALPHA_DTPREL64
	  && conflict->lookup.tls == conflict->conflict.tls
	  && conflict->lookupval == conflict->conflictval)
	return 0;

      value = conflict_lookup_value (conflict);
    }
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ALPHA_GLOB_DAT:
    case R_ALPHA_REFQUAD:
      ret->r_addend = value + rela->r_addend;
      break;
    case R_ALPHA_JMP_SLOT:
      ret->r_addend = value + rela->r_addend;
      if (alpha_is_indirect_plt (dso, rela, relaaddr))
	ret->r_info = GELF_R_INFO (0, R_ALPHA_GLOB_DAT);
      else
	{
	  relaaddr -= dso->info[DT_JMPREL];
	  relaaddr /= sizeof (Elf64_Rela);
	  if (relaaddr > 0xffffff)
	    {
	      error (0, 0, "%s: Cannot create R_ALPHA_JMP_SLOT conflict against .rel.plt with more than 16M entries",
		     dso->filename);
	      return 1;
	    }
	  ret->r_info = GELF_R_INFO (0, (relaaddr << 8) | R_ALPHA_JMP_SLOT);
	}
      break;
    case R_ALPHA_DTPMOD64:
    case R_ALPHA_DTPREL64:
    case R_ALPHA_TPREL64:
      if (conflict != NULL
	  && (conflict->reloc_class != RTYPE_CLASS_TLS
	      || conflict->lookup.tls == NULL))
	{
	  error (0, 0, "%s: TLS reloc not resolving to STT_TLS symbol",
		 dso->filename);
	  return 1;
	}
      tls = conflict ? conflict->lookup.tls : info->curtls;
      ret->r_info = GELF_R_INFO (0, R_ALPHA_GLOB_DAT);
      switch (GELF_R_TYPE (rela->r_info))
	{
	case R_ALPHA_DTPMOD64:
	  ret->r_addend = tls->modid;
	  break;
	case R_ALPHA_DTPREL64:
	  ret->r_addend = value + rela->r_addend;
	  break;
	case R_ALPHA_TPREL64:
	  ret->r_addend = value + rela->r_addend + tls->offset;
	  break;
	}
      break;
    default:
      error (0, 0, "%s: Unknown Alpha relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
alpha_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: Alpha doesn't support REL relocs", dso->filename);
  return 1;
}

static int
alpha_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
alpha_arch_prelink (struct prelink_info *info)
{
  DSO *dso;

  /* Correct sh_entsize on .plt sections.  */
  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT] + 16);
      assert (sec != -1);
      if (dso->shdr[sec].sh_type == SHT_PROGBITS
	  && dso->shdr[sec].sh_entsize == 32)
	dso->shdr[sec].sh_entsize = 0;
    }
  return 0;
}

static int
alpha_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  int sec;
  Elf_Scn *scn;
  Elf_Data *data;
  GElf_Sym sym;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ALPHA_NONE:
    case R_ALPHA_RELATIVE:
      break;
    case R_ALPHA_JMP_SLOT:
      relaaddr -= dso->info[DT_JMPREL];
      relaaddr /= sizeof (Elf64_Rela);
      relaaddr *= 12;
      relaaddr += dso->info[DT_PLTGOT] + 32;
      /* br at,.plt  */
      write_le32 (dso, relaaddr,
		  0xc39fffff - (relaaddr - dso->info[DT_PLTGOT]) / 4);
      write_le64 (dso, relaaddr + 4, 0);
      write_le64 (dso, rela->r_offset, relaaddr);
      break;
    case R_ALPHA_GLOB_DAT:
      /* This is ugly.  Linker doesn't clear memory at r_offset of GLOB_DAT
	 reloc, but instead puts in sym.st_value + addend.  */
      sec = addr_to_sec (dso, relaaddr);
      assert (sec != -1);
      sec = dso->shdr[sec].sh_link;
      assert (sec > 0 && sec < dso->ehdr.e_shnum);
      scn = dso->scn[sec];
      data = elf_getdata (scn, NULL);
      assert (data != NULL && elf_getdata (scn, data) == NULL);
      assert (GELF_R_SYM (rela->r_info)
	      <= dso->shdr[sec].sh_size / sizeof (Elf64_Sym));
      gelfx_getsym (dso->elf, data, GELF_R_SYM (rela->r_info), &sym);
      write_le64 (dso, rela->r_offset, sym.st_value + rela->r_addend);
      break;
    case R_ALPHA_REFQUAD:
    case R_ALPHA_DTPMOD64:
    case R_ALPHA_DTPREL64:
    case R_ALPHA_TPREL64:
      write_le64 (dso, rela->r_offset, 0);
      break;
    default:
      error (0, 0, "%s: Unknown alpha relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
alpha_reloc_size (int reloc_type)
{
  return 8;
}

static int
alpha_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_ALPHA_JMP_SLOT:
      return RTYPE_CLASS_PLT;
    case R_ALPHA_DTPMOD64:
    case R_ALPHA_DTPREL64:
    case R_ALPHA_TPREL64:
      return RTYPE_CLASS_TLS;
    default:
      return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "Alpha",
  .class = ELFCLASS64,
  .machine = EM_ALPHA,
  .alternate_machine = { EM_FAKE_ALPHA },
  .R_JMP_SLOT = R_ALPHA_JMP_SLOT,
  .R_COPY = -1,
  .R_RELATIVE = R_ALPHA_RELATIVE,
  .rtype_class_valid = RTYPE_CLASS_VALID,
  .dynamic_linker = "/lib/ld-linux.so.2",
  .adjust_dyn = alpha_adjust_dyn,
  .adjust_rel = alpha_adjust_rel,
  .adjust_rela = alpha_adjust_rela,
  .prelink_rel = alpha_prelink_rel,
  .prelink_rela = alpha_prelink_rela,
  .prelink_conflict_rel = alpha_prelink_conflict_rel,
  .prelink_conflict_rela = alpha_prelink_conflict_rela,
  .apply_conflict_rela = alpha_apply_conflict_rela,
  .apply_rel = alpha_apply_rel,
  .apply_rela = alpha_apply_rela,
  .rel_to_rela = alpha_rel_to_rela,
  .need_rel_to_rela = alpha_need_rel_to_rela,
  .reloc_size = alpha_reloc_size,
  .reloc_class = alpha_reloc_class,
  .max_reloc_size = 8,
  .arch_prelink = alpha_arch_prelink,
  .undo_prelink_rela = alpha_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0x0000020000000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x0000020001000000LL,
  .mmap_end =  0x0000020100000000LL,
  .max_page_size = 0x10000,
  .page_size = 0x02000
};
