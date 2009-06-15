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
sh_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
	       GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf32_Addr data;

      if (sec == -1)
	return 0;

      data = read_une32 (dso, dyn->d_un.d_ptr);
      /* If .got.plt[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_ne32 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_une32 (dso, dyn->d_un.d_ptr + 4);
      /* If .got.plt[1] points to .plt + 36, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 36
		&& dso->shdr[i].sh_type == SHT_PROGBITS
		&& strcmp (strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[i].sh_name), ".plt") == 0)
	      {
		write_ne32 (dso, dyn->d_un.d_ptr + 4, data + adjust);
		break;
	      }
	}
    }
  return 0;
}

static int
sh_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
	       GElf_Addr adjust)
{
  error (0, 0, "%s: SH doesn't support REL relocs", dso->filename);
  return 1;
}

static int
sh_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		GElf_Addr adjust)
{
  Elf32_Addr data;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SH_RELATIVE:
      if (rela->r_addend && (Elf32_Addr) rela->r_addend >= start)
	{
	  rela->r_addend += (Elf32_Sword) adjust;
	  break;
	}
      /* FALLTHROUGH */
    case R_SH_JMP_SLOT:
      data = read_une32 (dso, rela->r_offset);
      if (data >= start)
	write_ne32 (dso, rela->r_offset, data + adjust);
      break;
      break;
    }
  return 0;
}

static int
sh_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: SH doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
sh_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		 GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;

  dso = info->dso;
  if (GELF_R_TYPE (rela->r_info) == R_SH_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_SH_RELATIVE)
    {
      if (rela->r_addend)
	write_ne32 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SH_GLOB_DAT:
    case R_SH_JMP_SLOT:
    case R_SH_DIR32:
      write_ne32 (dso, rela->r_offset, value);
      break;
    case R_SH_REL32:
      write_ne32 (dso, rela->r_offset, value - rela->r_addend);
      break;
    case R_SH_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_SH_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown sh relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
sh_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			char *buf, GElf_Addr dest_addr)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SH_GLOB_DAT:
    case R_SH_JMP_SLOT:
    case R_SH_DIR32:
      buf_write_ne32 (info->dso, buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
sh_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: SH doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
sh_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SH_NONE:
      break;
    case R_SH_GLOB_DAT:
    case R_SH_JMP_SLOT:
    case R_SH_DIR32:
      buf_write_ne32 (info->dso, buf, value);
      break;
    case R_SH_REL32:
      buf_write_ne32 (info->dso, buf, value - rela->r_offset);
      break;
    case R_SH_COPY:
      abort ();
    case R_SH_RELATIVE:
      error (0, 0, "%s: R_SH_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
sh_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			 GElf_Addr reladdr)
{
  error (0, 0, "%s: SH doesn't support REL relocs", dso->filename);
  return 1;
}

static int
sh_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			  GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_SH_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_SH_NONE
      || info->dso == dso)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  else if (conflict->ifunc)
    {
      error (0, 0, "%s: STT_GNU_IFUNC not handled on SuperH yet",
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
    case R_SH_REL32:
      value -= rela->r_offset;
      ret->r_info = GELF_R_INFO (0, R_SH_DIR32);
      /* FALLTHROUGH */
    case R_SH_DIR32:
      if ((rela->r_offset & 3) == 0)
	ret->r_info = GELF_R_INFO (0, R_SH_GLOB_DAT);
      /* FALLTHROUGH */
    case R_SH_GLOB_DAT:
    case R_SH_JMP_SLOT:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend);
      break;
    case R_SH_COPY:
      error (0, 0, "R_SH_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown sh relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
sh_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  return 0;
}

static int
sh_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
sh_arch_prelink (struct prelink_info *info)
{
  DSO *dso;
  int i;

  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 36 into got[1].
	 .plt + 36 is what got[3] contains unless prelinking.  */
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

      if (i == dso->ehdr.e_shnum)
	return 0;
      data = dso->shdr[i].sh_addr + 36;
      write_ne32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
sh_arch_undo_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Clear got[1] if it contains address of .plt + 36.  */
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

      if (i == dso->ehdr.e_shnum)
	return 0;
      data = read_une32 (dso, dso->info[DT_PLTGOT] + 4);
      if (data == dso->shdr[i].sh_addr + 36)
	write_ne32 (dso, dso->info[DT_PLTGOT] + 4, 0);
    }

  return 0;
}

static int
sh_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  int sec;
  const char *name;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_SH_NONE:
      break;
    case R_SH_RELATIVE:
      if (rela->r_addend)
	write_le32 (dso, rela->r_offset, 0);
      break;
    case R_SH_JMP_SLOT:
      sec = addr_to_sec (dso, rela->r_offset);
      name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[sec].sh_name);
      if (sec == -1 || (strcmp (name, ".got") && strcmp (name, ".got.plt")))
	{
	  error (0, 0, "%s: R_SH_JMP_SLOT not pointing into .got section",
		 dso->filename);
	  return 1;
	}
      else
	{
	  Elf32_Addr data = read_une32 (dso, dso->shdr[sec].sh_addr + 4);

	  assert (rela->r_offset >= dso->shdr[sec].sh_addr + 12);
	  assert (((rela->r_offset - dso->shdr[sec].sh_addr) & 3) == 0);
	  write_ne32 (dso, rela->r_offset,
		      7 * (rela->r_offset - dso->shdr[sec].sh_addr - 12)
		      + data);
	}
      break;
    case R_SH_GLOB_DAT:
    case R_SH_DIR32:
    case R_SH_REL32:
      write_ne32 (dso, rela->r_offset, 0);
      break;
    case R_SH_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_SH_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown sh relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
sh_reloc_size (int reloc_type)
{
  return 4;
}

static int
sh_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_SH_COPY: return RTYPE_CLASS_COPY;
    case R_SH_JMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "SuperH",
  .class = ELFCLASS32,
  .machine = EM_SH,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_SH_JMP_SLOT,
  .R_COPY = R_SH_COPY,
  .R_RELATIVE = R_SH_RELATIVE,
  .rtype_class_valid = RTYPE_CLASS_VALID,
  .dynamic_linker = "/lib/ld-linux.so.2",
  .adjust_dyn = sh_adjust_dyn,
  .adjust_rel = sh_adjust_rel,
  .adjust_rela = sh_adjust_rela,
  .prelink_rel = sh_prelink_rel,
  .prelink_rela = sh_prelink_rela,
  .prelink_conflict_rel = sh_prelink_conflict_rel,
  .prelink_conflict_rela = sh_prelink_conflict_rela,
  .apply_conflict_rela = sh_apply_conflict_rela,
  .apply_rel = sh_apply_rel,
  .apply_rela = sh_apply_rela,
  .rel_to_rela = sh_rel_to_rela,
  .need_rel_to_rela = sh_need_rel_to_rela,
  .reloc_size = sh_reloc_size,
  .reloc_class = sh_reloc_class,
  .max_reloc_size = 4,
  .arch_prelink = sh_arch_prelink,
  .arch_undo_prelink = sh_arch_undo_prelink,
  .undo_prelink_rela = sh_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0x29555000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x30000000,
  .mmap_end =  0x40000000,
  .max_page_size = 0x2000,
  .page_size = 0x1000
};
