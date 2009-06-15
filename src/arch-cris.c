/* Copyright (C) 2001, 2002, 2004, 2009 Red Hat, Inc.
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
cris_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf32_Addr data;

      if (sec == -1)
	return 0;

      data = read_ule32 (dso, dyn->d_un.d_ptr);
      /* If .got[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_le32 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_ule32 (dso, dyn->d_un.d_ptr + 4);
      /* If .got[1] points to .plt + 28, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 28
		&& dso->shdr[i].sh_type == SHT_PROGBITS
		&& strcmp (strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[i].sh_name), ".plt") == 0)
	      {
		write_le32 (dso, dyn->d_un.d_ptr + 4, data + adjust);
		break;
	      }
	}
    }
  return 0;
}

static int
cris_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  error (0, 0, "%s: CRIS doesn't support REL relocs", dso->filename);
  return 1;
}

static int
cris_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  Elf32_Addr data;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_CRIS_RELATIVE:
      if ((Elf32_Addr) rela->r_addend >= start)
	rela->r_addend += (Elf32_Sword) adjust;
      break;
    case R_CRIS_JUMP_SLOT:
      data = read_ule32 (dso, rela->r_offset);
      if (data >= start)
	write_le32 (dso, rela->r_offset, data + adjust);
      break;
      break;
    }
  return 0;
}

static int
cris_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: CRIS doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
cris_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;

  dso = info->dso;
  if (GELF_R_TYPE (rela->r_info) == R_CRIS_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_CRIS_RELATIVE)
    {
      write_le32 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_CRIS_GLOB_DAT:
    case R_CRIS_JUMP_SLOT:
    case R_CRIS_32:
      write_le32 (dso, rela->r_offset, value);
      break;
    case R_CRIS_16:
      write_le16 (dso, rela->r_offset, value);
      break;
    case R_CRIS_8:
      write_8 (dso, rela->r_offset, value);
      break;
    case R_CRIS_32_PCREL:
      write_le32 (dso, rela->r_offset, value - rela->r_offset - 4);
      break;
    case R_CRIS_16_PCREL:
      write_le16 (dso, rela->r_offset, value - rela->r_offset - 2);
      break;
    case R_CRIS_8_PCREL:
      write_8 (dso, rela->r_offset, value - rela->r_offset - 1);
      break;
    case R_CRIS_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_CRIS_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown cris relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
cris_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf, GElf_Addr dest_addr)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_CRIS_GLOB_DAT:
    case R_CRIS_JUMP_SLOT:
    case R_CRIS_32:
      buf_write_le32 (buf, rela->r_addend);
      break;
    case R_CRIS_16:
      buf_write_le16 (buf, rela->r_addend);
      break;
    case R_CRIS_8:
      buf_write_8 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
cris_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: CRIS doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
cris_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_CRIS_NONE:
      break;
    case R_CRIS_GLOB_DAT:
    case R_CRIS_JUMP_SLOT:
    case R_CRIS_32:
      buf_write_le32 (buf, value);
      break;
    case R_CRIS_16:
      buf_write_le16 (buf, value);
      break;
    case R_CRIS_8:
      buf_write_8 (buf, value);
      break;
    case R_CRIS_32_PCREL:
      buf_write_le32 (buf, value - rela->r_offset - 4);
      break;
    case R_CRIS_16_PCREL:
      buf_write_le16 (buf, value - rela->r_offset - 2);
      break;
    case R_CRIS_8:
      buf_write_8 (buf, value - rela->r_offset - 1);
      break;
    case R_CRIS_COPY:
      abort ();
    case R_CRIS_RELATIVE:
      error (0, 0, "%s: R_CRIS_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
cris_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			   GElf_Addr reladdr)
{
  error (0, 0, "%s: CRIS doesn't support REL relocs", dso->filename);
  return 1;
}

static int
cris_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_CRIS_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_CRIS_NONE
      || info->dso == dso)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  else if (conflict->ifunc)
    {
      error (0, 0, "%s: STT_GNU_IFUNC not handled on CRIS yet",
	     dso->filename);
      return 1;
    }
  value = conflict_lookup_value (conflict);
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_CRIS_GLOB_DAT:
    case R_CRIS_JUMP_SLOT:
    case R_CRIS_32:
    case R_CRIS_16:
    case R_CRIS_8:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend);
      break;
    case R_CRIS_32_PCREL:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend
				     - rela->r_offset - 4);
      ret->r_info = GELF_R_INFO (0, R_CRIS_32);
      break;
    case R_CRIS_16_PCREL:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend
				     - rela->r_offset - 2);
      ret->r_info = GELF_R_INFO (0, R_CRIS_16);
      break;
    case R_CRIS_8_PCREL:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend
				     - rela->r_offset - 1);
      ret->r_info = GELF_R_INFO (0, R_CRIS_8);
      break;
    case R_CRIS_COPY:
      error (0, 0, "R_CRIS_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown cris relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
cris_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  return 0;
}

static int
cris_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
cris_arch_prelink (struct prelink_info *info)
{
  DSO *dso;
  int i;

  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 28 into got[1].
	 .plt + 28 is what got[3] contains unless prelinking.  */
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT]);
      Elf32_Addr data;

      if (sec == -1)
	return 1;

      for (i = 1; i < dso->ehdr.e_shnum; i++)
	if (dso->shdr[i].sh_type == SHT_PROGBITS
	    && ! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name),
			 ".plt"))
	break;

      assert (i < dso->ehdr.e_shnum);
      data = dso->shdr[i].sh_addr + 28;
      write_le32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
cris_reloc_size (int reloc_type)
{
  switch (reloc_type)
    {
    case R_CRIS_16:
    case R_CRIS_16_PCREL:
      return 2;
    case R_CRIS_8:
    case R_CRIS_8_PCREL:
      return 1;
    default:
      return 4;
    }
}

static int
cris_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_CRIS_COPY: return RTYPE_CLASS_COPY;
    case R_CRIS_JUMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "CRIS",
  .class = ELFCLASS32,
  .machine = EM_CRIS,
  .alternate_machine = { EM_NONE },
  .R_JUMP_SLOT = R_CRIS_JUMP_SLOT,
  .R_COPY = R_CRIS_COPY,
  .R_RELATIVE = R_CRIS_RELATIVE,
  .rtype_class_valid = RTYPE_CLASS_VALID,
  .dynamic_linker = "/lib/ld.so.1",
  .adjust_dyn = cris_adjust_dyn,
  .adjust_rel = cris_adjust_rel,
  .adjust_rela = cris_adjust_rela,
  .prelink_rel = cris_prelink_rel,
  .prelink_rela = cris_prelink_rela,
  .prelink_conflict_rel = cris_prelink_conflict_rel,
  .prelink_conflict_rela = cris_prelink_conflict_rela,
  .apply_conflict_rela = cris_apply_conflict_rela,
  .apply_rel = cris_apply_rel,
  .apply_rela = cris_apply_rela,
  .rel_to_rela = cris_rel_to_rela,
  .need_rel_to_rela = cris_need_rel_to_rela,
  .reloc_size = cris_reloc_size,
  .reloc_class = cris_reloc_class,
  .max_reloc_size = 4,
  .arch_prelink = cris_arch_prelink,
  /* Although TASK_UNMAPPED_BASE is 0x3aaaa000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x3c000000,
  .mmap_end =  0x48000000,
  .max_page_size = 0x2000,
  .page_size = 0x2000
};
