/* Copyright (C) 2001, 2002, 2003, 2004, 2009, 2013 Red Hat, Inc.
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
s390x_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		  GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf64_Addr data;

      if (sec == -1)
	return 0;

      data = read_ube64 (dso, dyn->d_un.d_ptr);
      /* If .got.plt[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_be64 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_ube64 (dso, dyn->d_un.d_ptr + 8);
      /* If .got.plt[1] points to .plt + 0x2e, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 0x2e
		&& dso->shdr[i].sh_type == SHT_PROGBITS
		&& strcmp (strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[i].sh_name), ".plt") == 0)
	      {
		write_be64 (dso, dyn->d_un.d_ptr + 8, data + adjust);
		break;
	      }
	}
    }
  return 0;
}

static int
s390x_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		  GElf_Addr adjust)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390x_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		   GElf_Addr adjust)
{
  Elf64_Addr addr;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_RELATIVE:
      if (rela->r_addend >= start)
	{
	  addr = read_ube64 (dso, rela->r_offset);
	  if (addr == rela->r_addend)
	    write_be64 (dso, rela->r_offset, addr + adjust);
	  rela->r_addend += adjust;
	}
      break;
    case R_390_IRELATIVE:
      if (rela->r_addend >= start)
	/* Adjust the resolver function address.  */
	rela->r_addend += adjust;
      /* FALLTHROUGH */
    case R_390_JMP_SLOT:
      /* Adjust the address in the GOT slot.  */
      addr = read_ube64 (dso, rela->r_offset);
      if (addr >= start)
	write_be64 (dso, rela->r_offset, addr + adjust);
      break;
    }
  return 0;
}

static int
s390x_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
s390x_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		    GElf_Addr relaaddr)
{
  DSO *dso = info->dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_390_NONE
      || GELF_R_TYPE (rela->r_info) == R_390_IRELATIVE)
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_390_RELATIVE)
    {
      write_be64 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
    case R_390_64:
      write_be64 (dso, rela->r_offset, value);
      break;
    case R_390_PC64:
      write_be64 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_390_32:
      write_be32 (dso, rela->r_offset, value);
      break;
    case R_390_PC32:
      write_be32 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_390_PC32DBL:
    case R_390_PLT32DBL:
      write_be32 (dso, rela->r_offset,
		  ((Elf32_Sword) (value - rela->r_offset)) >> 1);
      break;
    case R_390_16:
      write_be16 (dso, rela->r_offset, value);
      break;
    case R_390_PC16:
      write_be16 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_390_PC16DBL:
    case R_390_PLT16DBL:
      write_be16 (dso, rela->r_offset,
		  ((int16_t) (value - rela->r_offset)) >> 1);
      break;
    case R_390_8:
      write_8 (dso, rela->r_offset, value);
      break;
    case R_390_TLS_DTPOFF:
      write_be64 (dso, rela->r_offset, value);
      break;
    /* DTPMOD and TPOFF is impossible to predict in shared libraries
       unless prelink sets the rules.  */
    case R_390_TLS_DTPMOD:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_390_TLS_DTPMOD reloc in executable?",
		 dso->filename);
	  return 1;
	}
      break;
    case R_390_TLS_TPOFF:
      if (dso->ehdr.e_type == ET_EXEC && info->resolvetls)
	write_be64 (dso, rela->r_offset, value - info->resolvetls->offset);
      break;
    case R_390_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_390_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown S390 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
s390x_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			   char *buf, GElf_Addr dest_addr)
{
  GElf_Rela *ret;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_64:
      buf_write_be64 (buf, rela->r_addend);
      break;
    case R_390_32:
      buf_write_be32 (buf, rela->r_addend);
      break;
    case R_390_16:
      buf_write_be16 (buf, rela->r_addend);
      break;
    case R_390_8:
      buf_write_8 (buf, rela->r_addend);
      break;
    case R_390_IRELATIVE:
      if (dest_addr == 0)
	return 5;
      ret = prelink_conflict_add_rela (info);
      if (ret == NULL)
	return 1;
      ret->r_offset = dest_addr;
      ret->r_info = GELF_R_INFO (0, R_390_IRELATIVE);
      ret->r_addend = rela->r_addend;
      break;
    default:
      abort ();
    }
  return 0;
}

static int
s390x_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
s390x_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_NONE:
      break;
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
    case R_390_64:
      buf_write_be64 (buf, value);
      break;
    case R_390_PC64:
      buf_write_be64 (buf, value - rela->r_offset);
      break;
    case R_390_32:
      buf_write_be32 (buf, value);
      break;
    case R_390_PC32:
      buf_write_be32 (buf, value - rela->r_offset);
      break;
    case R_390_PC32DBL:
    case R_390_PLT32DBL:
      buf_write_be32 (buf, ((Elf32_Sword) (value - rela->r_offset)) >> 1);
      break;
    case R_390_16:
      buf_write_be16 (buf, value);
      break;
    case R_390_PC16:
      buf_write_be16 (buf, value - rela->r_offset);
      break;
    case R_390_PC16DBL:
    case R_390_PLT16DBL:
      buf_write_be16 (buf, ((int16_t) (value - rela->r_offset)) >> 1);
      break;
    case R_390_8:
      buf_write_8 (buf, value);
      break;
    case R_390_COPY:
      abort ();
    case R_390_RELATIVE:
      error (0, 0, "%s: R_390_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
s390x_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			    GElf_Addr reladdr)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390x_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			     GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *ret;
  int r_type;

  if (GELF_R_TYPE (rela->r_info) == R_390_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_390_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    {
      switch (GELF_R_TYPE (rela->r_info))
	{
	/* Even local DTPMOD and TPOFF relocs need conflicts.  */
	case R_390_TLS_DTPMOD:
	case R_390_TLS_TPOFF:
	  if (info->curtls == NULL || info->dso == dso)
	    return 0;
	  break;
	/* IRELATIVE always need conflicts.  */
	case R_390_IRELATIVE:
	  break;
	default:
	  return 0;
	}
      value = 0;
    }
  else if (info->dso == dso && !conflict->ifunc)
    return 0;
  else
    {
      /* DTPOFF wants to see only real conflicts, not lookups
	 with reloc_class RTYPE_CLASS_TLS.  */
      if (GELF_R_TYPE (rela->r_info) == R_390_TLS_DTPOFF
	  && conflict->lookup.tls == conflict->conflict.tls
	  && conflict->lookupval == conflict->conflictval)
	return 0;

      value = conflict_lookup_value (conflict);
    }
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  r_type = GELF_R_TYPE (rela->r_info);
  value += rela->r_addend;
  switch (r_type)
    {
    case R_390_PC64:
      value -= rela->r_offset;
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
      r_type = R_390_64;
    case R_390_64:
    case R_390_IRELATIVE:
      ret->r_addend = value;
      if (conflict != NULL && conflict->ifunc)
	r_type = R_390_IRELATIVE;
      break;
    case R_390_PC32:
      value -= rela->r_offset;
    case R_390_32:
      ret->r_addend = (Elf32_Addr) value;
      r_type = R_390_32;
      break;
    case R_390_PC32DBL:
    case R_390_PLT32DBL:
      ret->r_addend
	= (Elf32_Addr) (((Elf32_Sword) (value - rela->r_offset)) >> 1);
      r_type = R_390_32;
      break;
    case R_390_PC16:
      value -= rela->r_offset;
    case R_390_16:
      ret->r_addend = (Elf32_Half) value;
      r_type = R_390_16;
      break;
    case R_390_PC16DBL:
    case R_390_PLT16DBL:
      ret->r_addend = (Elf32_Half) (((int16_t) (value - rela->r_offset)) >> 1);
      r_type = R_390_16;
      break;
    case R_390_8:
      ret->r_addend = value & 0xff;
      break;
    case R_390_COPY:
      error (0, 0, "R_390_COPY should not be present in shared libraries");
      return 1;
    case R_390_TLS_DTPMOD:
    case R_390_TLS_DTPOFF:
    case R_390_TLS_TPOFF:
      if (conflict != NULL
	  && (conflict->reloc_class != RTYPE_CLASS_TLS
	      || conflict->lookup.tls == NULL))
	{
	  error (0, 0, "%s: TLS reloc not resolving to STT_TLS symbol",
		 dso->filename);
	  return 1;
	}
      tls = conflict ? conflict->lookup.tls : info->curtls;
      switch (r_type)
	{
	case R_390_TLS_DTPMOD:
	  ret->r_addend = tls->modid;
	  break;
	case R_390_TLS_DTPOFF:
	  ret->r_addend = value;
	  break;
	case R_390_TLS_TPOFF:
	  ret->r_addend = value - tls->offset;
	  break;
	}
      r_type = R_390_64;
      break;
    default:
      error (0, 0, "%s: Unknown S390 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  ret->r_info = GELF_R_INFO (0, r_type);
  return 0;
}

static int
s390x_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: S390 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
s390x_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
s390x_arch_prelink (struct prelink_info *info)
{
  DSO *dso;
  int i;

  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 0x2e into got[1].
	 .plt + 0x2e is what got[3] contains unless prelinking.  */
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT]);
      Elf64_Addr data;

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
      data = dso->shdr[i].sh_addr + 0x2e;
      write_be64 (dso, dso->info[DT_PLTGOT] + 8, data);
    }

  return 0;
}

static int
s390x_arch_undo_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Clear got[1] if it contains address of .plt + 0x2e.  */
      int sec = addr_to_sec (dso, dso->info[DT_PLTGOT]);
      Elf64_Addr data;

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
      data = read_ube64 (dso, dso->info[DT_PLTGOT] + 8);
      if (data == dso->shdr[i].sh_addr + 0x2e)
	write_be64 (dso, dso->info[DT_PLTGOT] + 8, 0);
    }

  return 0;
}

static int
s390x_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  int sec;
  const char *name;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_390_NONE:
    case R_390_RELATIVE:
    case R_390_IRELATIVE:
      break;
    case R_390_JMP_SLOT:
      sec = addr_to_sec (dso, rela->r_offset);
      name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[sec].sh_name);
      if (sec == -1 || (strcmp (name, ".got") && strcmp (name, ".got.plt")))
	{
	  error (0, 0, "%s: R_390_JMP_SLOT not pointing into .got section",
		 dso->filename);
	  return 1;
	}
      else
	{
	  Elf64_Addr data = read_ube64 (dso, dso->shdr[sec].sh_addr + 8);

	  assert (rela->r_offset >= dso->shdr[sec].sh_addr + 24);
	  assert (((rela->r_offset - dso->shdr[sec].sh_addr) & 7) == 0);
	  write_be64 (dso, rela->r_offset,
		      4 * (rela->r_offset - dso->shdr[sec].sh_addr - 24)
		      + data);
	}
      break;
    case R_390_GLOB_DAT:
    case R_390_64:
    case R_390_PC64:
    case R_390_TLS_DTPMOD:
    case R_390_TLS_DTPOFF:
    case R_390_TLS_TPOFF:
      write_be64 (dso, rela->r_offset, 0);
      break;
    case R_390_32:
    case R_390_PC32:
    case R_390_PC32DBL:
    case R_390_PLT32DBL:
      write_be32 (dso, rela->r_offset, 0);
      break;
    case R_390_16:
    case R_390_PC16:
    case R_390_PC16DBL:
    case R_390_PLT16DBL:
      write_be16 (dso, rela->r_offset, 0);
      break;
    case R_390_8:
      write_8 (dso, rela->r_offset, 0);
      break;
    case R_390_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_390_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown s390x relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
s390x_reloc_size (int reloc_type)
{
  switch (reloc_type)
    {
    case R_390_GLOB_DAT:
    case R_390_JMP_SLOT:
    case R_390_64:
    case R_390_PC64:
    case R_390_IRELATIVE:
      return 8;
    case R_390_32:
    case R_390_PC32:
    case R_390_PC32DBL:
    case R_390_PLT32DBL:
    default:
      return 4;
    case R_390_16:
    case R_390_PC16:
    case R_390_PC16DBL:
    case R_390_PLT16DBL:
      return 2;
    case R_390_8:
      return 1;
    }
}

static int
s390x_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_390_COPY: return RTYPE_CLASS_COPY;
    case R_390_JMP_SLOT: return RTYPE_CLASS_PLT;
    case R_390_TLS_DTPMOD:
    case R_390_TLS_DTPOFF:
    case R_390_TLS_TPOFF:
      return RTYPE_CLASS_TLS;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "S390",
  .class = ELFCLASS64,
  .machine = EM_S390,
  .alternate_machine = { 0xA390 },
  .R_JMP_SLOT = R_390_JMP_SLOT,
  .R_COPY = R_390_COPY,
  .R_RELATIVE = R_390_RELATIVE,
  .rtype_class_valid = RTYPE_CLASS_VALID,
  .dynamic_linker = "/lib/ld64.so.1",
  .adjust_dyn = s390x_adjust_dyn,
  .adjust_rel = s390x_adjust_rel,
  .adjust_rela = s390x_adjust_rela,
  .prelink_rel = s390x_prelink_rel,
  .prelink_rela = s390x_prelink_rela,
  .prelink_conflict_rel = s390x_prelink_conflict_rel,
  .prelink_conflict_rela = s390x_prelink_conflict_rela,
  .apply_conflict_rela = s390x_apply_conflict_rela,
  .apply_rel = s390x_apply_rel,
  .apply_rela = s390x_apply_rela,
  .rel_to_rela = s390x_rel_to_rela,
  .need_rel_to_rela = s390x_need_rel_to_rela,
  .reloc_size = s390x_reloc_size,
  .reloc_class = s390x_reloc_class,
  .max_reloc_size = 8,
  .arch_prelink = s390x_arch_prelink,
  .arch_undo_prelink = s390x_arch_undo_prelink,
  .undo_prelink_rela = s390x_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0x4000000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x4010000000LL,
  .mmap_end =  0x5000000000LL,
  .max_page_size = 0x1000,
  .page_size = 0x1000
};
