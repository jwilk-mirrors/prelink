/* Copyright (C) 2001, 2002, 2003, 2004 Red Hat, Inc.
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
#include "layout.h"

static int
i386_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PLTGOT)
    {
      int sec = addr_to_sec (dso, dyn->d_un.d_ptr);
      Elf32_Addr data;

      if (sec == -1)
	return 0;

      data = read_ule32 (dso, dyn->d_un.d_ptr);
      /* If .got.plt[0] points to _DYNAMIC, it needs to be adjusted.  */
      if (data == dso->shdr[n].sh_addr && data >= start)
	write_le32 (dso, dyn->d_un.d_ptr, data + adjust);

      data = read_ule32 (dso, dyn->d_un.d_ptr + 4);
      /* If .got.plt[1] points to .plt + 0x16, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr + 0x16
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
i386_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  Elf32_Addr data;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_RELATIVE:
    case R_386_JMP_SLOT:
      data = read_ule32 (dso, rel->r_offset);
      if (data >= start)
	write_le32 (dso, rel->r_offset, data + adjust);
      break;
    }
  return 0;
}

static int
i386_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  Elf32_Addr data;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_386_RELATIVE:
      if ((Elf32_Addr) rela->r_addend >= start)
	{
	  rela->r_addend += (Elf32_Sword) adjust;
	  /* Write it to the memory location as well.
	     Not necessary, but we can do it.  */
	  write_le32 (dso, rela->r_offset, rela->r_addend);
	}
      break;
    case R_386_JMP_SLOT:
      data = read_ule32 (dso, rela->r_offset);
      if (data >= start)
	write_le32 (dso, rela->r_offset, data + adjust);
      break;
      break;
    }
  return 0;
}

static int
i386_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rel->r_info) == R_386_RELATIVE
      || GELF_R_TYPE (rel->r_info) == R_386_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rel->r_info),
			 GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      write_le32 (dso, rel->r_offset, value);
      break;
    case R_386_32:
      {
	if (read_ule32 (dso, rel->r_offset))
	  {
	    error (0, 0, "%s: R_386_32 relocs with non-zero addend should not be present in prelinked REL sections",
		   dso->filename);
	    return 1;
	  }
	rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_386_GLOB_DAT);
	write_le32 (dso, rel->r_offset, value);
	/* Tell prelink_rel routine *rel has changed.  */
	return 2;
      }
    case R_386_PC32:
      error (0, 0, "%s: R_386_PC32 relocs should not be present in prelinked REL sections",
	     dso->filename);
      return 1;
    case R_386_TLS_DTPOFF32:
      write_le32 (dso, rel->r_offset, value);
      break;
    /* DTPMOD32 and TPOFF{32,} is impossible to predict unless prelink
       sets the rules.  Also for TPOFF{32,} there is REL->RELA problem.  */
    case R_386_TLS_DTPMOD32:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_386_TLS_DTPMOD32 reloc in executable?",
		 dso->filename);
	  return 1;
	}
      break;
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      if (dso->ehdr.e_type == ET_EXEC)
	error (0, 0, "%s: R_386_TLS_TPOFF relocs should not be present in prelinked ET_EXEC REL sections",
	       dso->filename);
      break;
    case R_386_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_386_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
i386_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_386_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_386_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      write_le32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_386_32:
      write_le32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_386_PC32:
      write_le32 (dso, rela->r_offset, value + rela->r_addend - rela->r_offset);
      break;
    case R_386_TLS_DTPOFF32:
      write_le32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    /* DTPMOD32 and TPOFF{32,} is impossible to predict unless prelink
       sets the rules.  */
    case R_386_TLS_DTPMOD32:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_386_TLS_DTPMOD32 reloc in executable?",
		 dso->filename);
	  return 1;
	}
      break;
    case R_386_TLS_TPOFF32:
      if (dso->ehdr.e_type == ET_EXEC && info->resolvetls)
	write_le32 (dso, rela->r_offset,
		    -(value + rela->r_addend - info->resolvetls->offset));
      break;
    case R_386_TLS_TPOFF:
      if (dso->ehdr.e_type == ET_EXEC && info->resolvetls)
	write_le32 (dso, rela->r_offset,
		    value + rela->r_addend - info->resolvetls->offset);
      break;
    case R_386_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_386_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
i386_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
    case R_386_32:
      buf_write_le32 (buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
i386_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rel->r_info),
			 GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_NONE:
      break;
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
      buf_write_le32 (buf, value);
      break;
    case R_386_32:
      buf_write_le32 (buf, value + read_ule32 (info->dso, rel->r_offset));
      break;
    case R_386_PC32:
      buf_write_le32 (buf, value + read_ule32 (info->dso, rel->r_offset)
			   - rel->r_offset);
      break;
    case R_386_COPY:
      abort ();
    case R_386_RELATIVE:
      error (0, 0, "%s: R_386_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
i386_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_386_NONE:
      break;
    case R_386_GLOB_DAT:
    case R_386_JMP_SLOT:
    case R_386_32:
      buf_write_le32 (buf, value + rela->r_addend);
      break;
    case R_386_PC32:
      buf_write_le32 (buf, value + rela->r_addend - rela->r_offset);
      break;
    case R_386_COPY:
      abort ();
    case R_386_RELATIVE:
      error (0, 0, "%s: R_386_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
i386_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			   GElf_Addr reladdr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rel->r_info) == R_386_RELATIVE
      || GELF_R_TYPE (rel->r_info) == R_386_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rel->r_info),
			       GELF_R_TYPE (rel->r_info));
  if (conflict == NULL)
    {
      if (info->curtls == NULL)
	return 0;
      switch (GELF_R_TYPE (rel->r_info))
	{
	/* Even local DTPMOD and TPOFF relocs need conflicts.  */
	case R_386_TLS_DTPMOD32:
	case R_386_TLS_TPOFF32:
	case R_386_TLS_TPOFF:
	  break;
	default:
	  return 0;
	}
      value = 0;
    }
  else
    {
      /* DTPOFF32 wants to see only real conflicts, not lookups
	 with reloc_class RTYPE_CLASS_TLS.  */
      if (GELF_R_TYPE (rel->r_info) == R_386_TLS_DTPOFF32
	  && conflict->lookup.tls == conflict->conflict.tls
	  && conflict->lookupval == conflict->conflictval)
	return 0;

      value = conflict_lookup_value (conflict);
    }
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rel->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_GLOB_DAT:
      ret->r_info = GELF_R_INFO (0, R_386_32);
      /* FALLTHROUGH */
    case R_386_JMP_SLOT:
      ret->r_addend = (Elf32_Sword) value;
      break;
    case R_386_32:
    case R_386_PC32:
      error (0, 0, "%s: R_386_%s32 relocs should not be present in prelinked REL sections",
	     dso->filename, GELF_R_TYPE (rel->r_info) == R_386_32 ? "" : "PC");
      return 1;
    case R_386_TLS_DTPMOD32:
    case R_386_TLS_DTPOFF32:
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      if (conflict != NULL
	  && (conflict->reloc_class != RTYPE_CLASS_TLS
	      || conflict->lookup.tls == NULL))
	{
	  error (0, 0, "%s: R_386_TLS not resolving to STT_TLS symbol",
		 dso->filename);
	  return 1;
	}
      tls = conflict ? conflict->lookup.tls : info->curtls;
      ret->r_info = GELF_R_INFO (0, R_386_32);
      switch (GELF_R_TYPE (rel->r_info))
	{
	case R_386_TLS_DTPMOD32:
	  ret->r_addend = tls->modid;
	  break;
	case R_386_TLS_DTPOFF32:
	  ret->r_addend = value;
	  break;
	case R_386_TLS_TPOFF32:
	  ret->r_addend = -(value + read_ule32 (dso, rel->r_offset)
			    - tls->offset);
	  break;
	case R_386_TLS_TPOFF:
	  ret->r_addend = value + read_ule32 (dso, rel->r_offset)
			  - tls->offset;
	}
      break;
    case R_386_COPY:
      error (0, 0, "R_386_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
i386_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rela->r_info) == R_386_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_386_NONE)
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
	/* Even local DTPMOD and TPOFF relocs need conflicts.  */
	case R_386_TLS_DTPMOD32:
	case R_386_TLS_TPOFF32:
	case R_386_TLS_TPOFF:
	  break;
	default:
	  return 0;
	}
      value = 0;
    }
  else
    {
      /* DTPOFF32 wants to see only real conflicts, not lookups
	 with reloc_class RTYPE_CLASS_TLS.  */
      if (GELF_R_TYPE (rela->r_info) == R_386_TLS_DTPOFF32
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
    case R_386_GLOB_DAT:
      ret->r_info = GELF_R_INFO (0, R_386_32);
      /* FALLTHROUGH */
    case R_386_JMP_SLOT:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend);
      break;
    case R_386_32:
      value += rela->r_addend;
      ret->r_addend = (Elf32_Sword) value;
      break;
    case R_386_PC32:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend - rela->r_offset);
      ret->r_info = GELF_R_INFO (0, R_386_32);
      break;
    case R_386_COPY:
      error (0, 0, "R_386_COPY should not be present in shared libraries");
      return 1;
    case R_386_TLS_DTPMOD32:
    case R_386_TLS_DTPOFF32:
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      if (conflict != NULL
	  && (conflict->reloc_class != RTYPE_CLASS_TLS
	      || conflict->lookup.tls == NULL))
	{
	  error (0, 0, "%s: R_386_TLS not resolving to STT_TLS symbol",
		 dso->filename);
	  return 1;
	}
      tls = conflict ? conflict->lookup.tls : info->curtls;
      ret->r_info = GELF_R_INFO (0, R_386_32);
      switch (GELF_R_TYPE (rela->r_info))
	{
	case R_386_TLS_DTPMOD32:
	  ret->r_addend = tls->modid;
	  break;
	case R_386_TLS_DTPOFF32:
	  ret->r_addend += value;
	  break;
	case R_386_TLS_TPOFF32:
	  ret->r_addend = -(value + rela->r_addend - tls->offset);
	  break;
	case R_386_TLS_TPOFF:
	  ret->r_addend = value + rela->r_addend - tls->offset;
	  break;
	}
      break;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
i386_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  rela->r_offset = rel->r_offset;
  rela->r_info = rel->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_JMP_SLOT:
      /* We should be never converting .rel.plt into .rela.plt.  */
      abort ();
    case R_386_RELATIVE:
    case R_386_32:
    case R_386_PC32:
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      rela->r_addend = (Elf32_Sword) read_ule32 (dso, rel->r_offset);
      break;
    case R_386_COPY:
    case R_386_GLOB_DAT:
    case R_386_TLS_DTPOFF32:
    case R_386_TLS_DTPMOD32:
      rela->r_addend = 0;
      break;
    }
  return 0;
}

static int
i386_need_rel_to_rela (DSO *dso, int first, int last)
{
  Elf_Data *data;
  Elf_Scn *scn;
  Elf32_Rel *rel, *relend;
  unsigned int val;

  while (first <= last)
    {
      data = NULL;
      scn = dso->scn[first++];
      while ((data = elf_getdata (scn, data)) != NULL)
	{
	  rel = (Elf32_Rel *) data->d_buf;
	  relend = rel + data->d_size / sizeof (Elf32_Rel);
	  for (; rel < relend; rel++)
	    switch (ELF32_R_TYPE (rel->r_info))
	      {
	      case R_386_32:
		val = read_ule32 (dso, rel->r_offset);
		/* R_386_32 with addend 0 can be converted
		   to R_386_GLOB_DAT and we don't have to convert
		   to RELA because of that.  */
		if (val == 0)
		  break;
		/* FALLTHROUGH */
	      case R_386_PC32:
		return 1;
	      case R_386_TLS_TPOFF32:
	      case R_386_TLS_TPOFF:
		/* In shared libraries TPOFF is changed always into
		   conflicts, for executables we need to preserve
		   original addend.  */
		if (dso->ehdr.e_type == ET_EXEC)
		  return 1;
		break;
	      }
	}
    }
  return 0;
}

static int
i386_arch_prelink (struct prelink_info *info)
{
  DSO *dso;
  int i;

  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt + 0x16 into got[1].
	 .plt + 0x16 is what got[3] contains unless prelinking.  */
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
      data = dso->shdr[i].sh_addr + 0x16;
      write_le32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
i386_arch_undo_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Clear got[1] if it contains address of .plt + 0x16.  */
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
      data = read_ule32 (dso, dso->info[DT_PLTGOT] + 4);
      if (data == dso->shdr[i].sh_addr + 0x16)
	write_le32 (dso, dso->info[DT_PLTGOT] + 4, 0);
    }

  return 0;
}

static int
i386_undo_prelink_rel (DSO *dso, GElf_Rel *rel, GElf_Addr reladdr)
{
  int sec;
  const char *name;

  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_NONE:
    case R_386_RELATIVE:
      break;
    case R_386_JMP_SLOT:
      sec = addr_to_sec (dso, rel->r_offset);
      name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[sec].sh_name);
      if (sec == -1 || (strcmp (name, ".got") && strcmp (name, ".got.plt")))
	{
	  error (0, 0, "%s: R_386_JMP_SLOT not pointing into .got section",
		 dso->filename);
	  return 1;
	}
      else
	{
	  Elf32_Addr data = read_ule32 (dso, dso->shdr[sec].sh_addr + 4);

	  assert (rel->r_offset >= dso->shdr[sec].sh_addr + 12);
	  assert (((rel->r_offset - dso->shdr[sec].sh_addr) & 3) == 0);
	  write_le32 (dso, rel->r_offset,
		      4 * (rel->r_offset - dso->shdr[sec].sh_addr - 12)
		      + data);
	}
      break;
    case R_386_GLOB_DAT:
      sec = addr_to_sec (dso, rel->r_offset);

      write_le32 (dso, rel->r_offset, 0);
      if (sec != -1)
	{
	  if (strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			      dso->shdr[sec].sh_name),
		      ".got"))
	    {
	      rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_386_32);
	      return 2;
	    }
	}
      break;
    case R_386_32:
    case R_386_PC32:
      error (0, 0, "%s: R_386_%s32 relocs should not be present in prelinked REL sections",
	     GELF_R_TYPE (rel->r_info) == R_386_32 ? "" : "PC", dso->filename);
      return 1;
    case R_386_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_386_COPY reloc in shared library?", dso->filename);
      return 1;
    case R_386_TLS_DTPMOD32:
    case R_386_TLS_DTPOFF32:
      write_le32 (dso, rel->r_offset, 0);
      break;
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      break;
    default:
      error (0, 0, "%s: Unknown i386 relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
i386_rela_to_rel (DSO *dso, GElf_Rela *rela, GElf_Rel *rel)
{
  rel->r_offset = rela->r_offset;
  rel->r_info = rela->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_386_JMP_SLOT:
      /* We should be never converting .rel.plt into .rela.plt
	 and thus never .rela.plt back to .rel.plt.  */
      abort ();
    case R_386_RELATIVE:
    case R_386_32:
    case R_386_PC32:
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      write_le32 (dso, rela->r_offset, rela->r_addend);
      break;
    case R_386_COPY:
    case R_386_GLOB_DAT:
    case R_386_TLS_DTPMOD32:
    case R_386_TLS_DTPOFF32:
      write_le32 (dso, rela->r_offset, 0);
      break;
    }
  return 0;
}

static int
i386_reloc_size (int reloc_type)
{
  assert (reloc_type != R_386_COPY);
  return 4;
}

static int
i386_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_386_COPY: return RTYPE_CLASS_COPY;
    case R_386_JMP_SLOT: return RTYPE_CLASS_PLT;
    case R_386_TLS_DTPMOD32:
    case R_386_TLS_DTPOFF32:
    case R_386_TLS_TPOFF32:
    case R_386_TLS_TPOFF:
      return RTYPE_CLASS_TLS;
    default: return RTYPE_CLASS_VALID;
    }
}

/* Library memory regions if --exec-shield in order of precedence:
   0x00101000 + (rand % 0x00cff000) .. 0x00e00000 bottom to top
   0x00101000 .. 0x00101000 + (rand % 0x00cff000) bottom to top
   0x02000000 + (rand % 0x06000000) .. 0x08000000 bottom to top
   0x02000000 .. 0x02000000 + (rand % 0x06000000) bottom to top
   0x41000000 + (rand % 0x0f000000) .. 0x50000000 bottom to top
   0x41000000 .. 0x41000000 + (rand % 0x0f000000) bottom to top  */

#define REG0S	0x00101000
#define REG0E	0x00e00000
#define REG1S	0x02000000
#define REG1E	0x08000000
#define REG2S	0x41000000
#define REG2E	0x50000000

struct i386_layout_data
{
  struct prelink_entry e[6];
  Elf32_Addr addrs[12];
};

static inline void
list_append (struct prelink_entry *x, struct prelink_entry *e)
{
  x->prev->next = e;
  e->prev = x->prev;
  e->next = NULL;
  x->prev = e;
}

static inline void
list_merge (struct prelink_entry *x, struct prelink_entry *e)
{
  struct prelink_entry *end = e->prev;
  x->prev->next = e;
  e->prev = x->prev;
  x->prev = end;
}

static int
i386_layout_libs_init (struct layout_libs *l)
{
  if (exec_shield)
    {
      int i;
      struct prelink_entry *e;

      l->mmap_base = REG0S;
      l->mmap_end = REG2E;
      /* Don't allow this to be overridden.  */
      mmap_reg_start = ~(GElf_Addr) 0;
      mmap_reg_end = ~(GElf_Addr) 0;
      for (i = 0; i < l->nlibs; ++i)
	{
	  e = l->libs[i];
	  if (e->done == 0)
	    continue;
	  if (e->base < REG0S
	      || (e->base < REG1S && e->layend > REG0E)
	      || (e->base < REG2S && e->layend > REG1E)
	      || e->layend > REG2E)
	    e->done = 0;
	}
    }
  else
    {
      l->mmap_base = REG2S;
      l->mmap_end = REG2E;
    }
  return 0;
}

static void
i386_find_free_addr (struct layout_libs *l, Elf32_Addr *ret,
		     Elf32_Addr beg, Elf32_Addr end, Elf32_Addr start)
{
  struct prelink_entry *e;
  Elf32_Addr low, hi;

  ret[0] = beg;
  ret[3] = end;
  for (e = l->list; e != NULL; e = e->next)
    if (e->base >= start)
      break;
  if (e == l->list)
    {
      ret[1] = ret[2] = start;
      return;
    }

  if (e == NULL)
    e = l->list;
  low = start;
  for (e = e->prev; ; e = e->prev)
    {
      if (e->base < beg)
	break;
      if (e->layend > low)
	low = e->base;
      if (e == l->list)
	break;
    }

  if (low == start)
    {
      ret[1] = ret[2] = start;
      return;
    }

  hi = start;
  for (; e; e = e->next)
    {
      if (e->base >= end)
	break;
      if (e->base >= hi)
	break;
      if (e->layend > hi)
	hi = e->layend;
    }

  assert (low >= beg && hi <= end);

  if (hi - start > start - low)
    start = low;
  else
    start = hi;

  ret[1] = ret[2] = start;
}

static int
i386_layout_libs_pre (struct layout_libs *l)
{
  Elf32_Addr mmap_start, virt;
  struct prelink_entry *e, *next;
  struct i386_layout_data *pld;
  int i;

  if (!exec_shield)
    {
      l->mmap_fin = l->mmap_end;
      l->fake = NULL;
      l->fakecnt = 0;
      return 0;
    }

  pld = calloc (sizeof (*pld), 1);
  if (pld == NULL)
    error (EXIT_FAILURE, ENOMEM, "Cannot lay libraries out");

  l->arch_data = pld;

  mmap_start = l->mmap_start - REG0S;
  /* Unless not randomizing, try not to make the first region
     too small, because otherwise it is likely libc.so as first
     big library would often end up at REG0S.  */
  virt = mmap_start % (REG0E - REG0S - 0x200000);
  i386_find_free_addr (l, pld->addrs + 0, REG0S, REG0E, REG0S + virt);
  virt = mmap_start % (REG1E - REG1S - 0x200000);
  i386_find_free_addr (l, pld->addrs + 4, REG1S, REG1E, REG1S + virt);
  virt = mmap_start % (REG0E - REG0S - 0x200000);
  i386_find_free_addr (l, pld->addrs + 8, REG2S, REG2E, REG2S + virt);
  i = 0;
  virt = pld->addrs[3] - pld->addrs[2];
  pld->e[0].u.tmp = -1;
  pld->e[0].base = virt;
  pld->e[0].end = pld->e[0].base;
  pld->e[0].layend = pld->e[0].end;
  pld->e[0].prev = &pld->e[0];
  next = NULL;
  for (e = l->list; e != NULL; e = next)
    {
      next = e->next;
      while (i < 5
	     && (e->base >= pld->addrs[2 * i + 1]
		 || pld->addrs[2 * i] == pld->addrs[2 * i + 1]))
	{
	  ++i;
	  pld->e[i].u.tmp = -1;
	  if (i & 1)
	    virt -= pld->addrs[2 * i + 1] - pld->addrs[2 * i];
	  else
	    {
	      virt += pld->addrs[2 * i - 1] - pld->addrs[2 * i - 4];
	      virt += pld->addrs[2 * i + 3] - pld->addrs[2 * i + 2];
	    }
	  pld->e[i].base = virt;
	  pld->e[i].end = pld->e[i].base;
	  pld->e[i].layend = pld->e[i].end;
	  pld->e[i].prev = &pld->e[i];
	}
      e->base += (Elf32_Sword) (virt - pld->addrs[2 * i]);
      e->end += (Elf32_Sword) (virt - pld->addrs[2 * i]);
      e->layend += (Elf32_Sword) (virt - pld->addrs[2 * i]);
      list_append (&pld->e[i], e);
    }
  while (i < 5)
    {
      ++i;
      pld->e[i].u.tmp = -1;
      if (i & 1)
	virt -= pld->addrs[2 * i + 1] - pld->addrs[2 * i];
      else
	{
	  virt += pld->addrs[2 * i - 1] - pld->addrs[2 * i - 4];
	  virt += pld->addrs[2 * i + 3] - pld->addrs[2 * i + 2];
	}
      pld->e[i].base = virt;
      pld->e[i].end = pld->e[i].base;
      pld->e[i].layend = pld->e[i].end;
      pld->e[i].prev = &pld->e[i];
    }
  l->list = &pld->e[1];
  list_merge (&pld->e[1], &pld->e[0]);
  list_merge (&pld->e[1], &pld->e[3]);
  list_merge (&pld->e[1], &pld->e[2]);
  list_merge (&pld->e[1], &pld->e[5]);
  list_merge (&pld->e[1], &pld->e[4]);

  l->mmap_start = 0;
  l->mmap_base = 0;
  l->mmap_fin = virt + pld->addrs[2 * i + 1] - pld->addrs[2 * i];
  l->mmap_end = l->mmap_fin;
  l->fakecnt = 6;
  l->fake = pld->e;

  return 0;
}

static int
i386_layout_libs_post (struct layout_libs *l)
{
  struct prelink_entry *e;
  struct i386_layout_data *pld = (struct i386_layout_data *) l->arch_data;
  Elf32_Sword adj = 0;
  int i;

  if (!exec_shield)
    return 0;

  for (i = 0, e = l->list; e != NULL; e = e->next)
    {
      if (e == &pld->e[i ^ 1])
	{
	  adj = pld->addrs[2 * (i ^ 1)] - e->base;
	  ++i;
	}
      else
	{
	  e->base += adj;
	  e->end += adj;
	  e->layend += adj;
	}
    }

  free (l->arch_data);
  return 0;
}

PL_ARCH = {
  .name = "i386",
  .class = ELFCLASS32,
  .machine = EM_386,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_386_JMP_SLOT,
  .R_COPY = R_386_COPY,
  .R_RELATIVE = R_386_RELATIVE,
  .dynamic_linker = "/lib/ld-linux.so.2",
  .adjust_dyn = i386_adjust_dyn,
  .adjust_rel = i386_adjust_rel,
  .adjust_rela = i386_adjust_rela,
  .prelink_rel = i386_prelink_rel,
  .prelink_rela = i386_prelink_rela,
  .prelink_conflict_rel = i386_prelink_conflict_rel,
  .prelink_conflict_rela = i386_prelink_conflict_rela,
  .apply_conflict_rela = i386_apply_conflict_rela,
  .apply_rel = i386_apply_rel,
  .apply_rela = i386_apply_rela,
  .rel_to_rela = i386_rel_to_rela,
  .rela_to_rel = i386_rela_to_rel,
  .need_rel_to_rela = i386_need_rel_to_rela,
  .reloc_size = i386_reloc_size,
  .reloc_class = i386_reloc_class,
  .max_reloc_size = 4,
  .arch_prelink = i386_arch_prelink,
  .arch_undo_prelink = i386_arch_undo_prelink,
  .undo_prelink_rel = i386_undo_prelink_rel,
  .layout_libs_init = i386_layout_libs_init,
  .layout_libs_pre = i386_layout_libs_pre,
  .layout_libs_post = i386_layout_libs_post,
  /* Although TASK_UNMAPPED_BASE is 0x40000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = REG2S,
  .mmap_end =  REG2E,
  .max_page_size = 0x1000,
  .page_size = 0x1000
};
