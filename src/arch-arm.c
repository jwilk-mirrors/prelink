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

static int
arm_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
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
      /* If .got.plt[1] points to .plt, it needs to be adjusted.  */
      if (data && data >= start)
	{
	  int i;

	  for (i = 1; i < dso->ehdr.e_shnum; i++)
	    if (data == dso->shdr[i].sh_addr
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
arm_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		 GElf_Addr adjust)
{
  Elf32_Addr data;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_RELATIVE:
    case R_ARM_JUMP_SLOT:
      data = read_une32 (dso, rel->r_offset);
      if (data >= start)
	write_ne32 (dso, rel->r_offset, data + adjust);
      break;
    }
  return 0;
}

static int
arm_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		  GElf_Addr adjust)
{
  Elf32_Addr data;

  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ARM_RELATIVE:
      if ((Elf32_Addr) rela->r_addend >= start)
	{
	  rela->r_addend += (Elf32_Sword) adjust;
	  /* Write it to the memory location as well.
	     Not necessary, but we can do it.  */
	  write_ne32 (dso, rela->r_offset, rela->r_addend);
	}
      break;
    case R_ARM_JUMP_SLOT:
      data = read_une32 (dso, rela->r_offset);
      if (data >= start)
	write_ne32 (dso, rela->r_offset, data + adjust);
      break;
      break;
    }
  return 0;
}

static int
arm_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  DSO *dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rel->r_info) == R_ARM_RELATIVE
      || GELF_R_TYPE (rel->r_info) == R_ARM_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rel->r_info),
			 GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
      write_ne32 (dso, rel->r_offset, value);
      break;
    case R_ARM_ABS32:
      {
	if (read_une32 (dso, rel->r_offset))
	  {
	    error (0, 0, "%s: R_ARM_ABS32 relocs with non-zero addend should not be present in prelinked REL sections",
		   dso->filename);
	    return 1;
	  }
	rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_ARM_GLOB_DAT);
	write_ne32 (dso, rel->r_offset, value);
	/* Tell prelink_rel routine *rel has changed.  */
	return 2;
      }
    case R_ARM_PC24:
      error (0, 0, "%s: R_ARM_PC24 relocs with non-zero addend should not be present in prelinked REL sections",
	     dso->filename);
      return 1;
    case R_ARM_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_ARM_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown arm relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
arm_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  DSO *dso;
  GElf_Addr value;
  Elf32_Sword val;

  if (GELF_R_TYPE (rela->r_info) == R_ARM_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_ARM_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  dso = info->dso;
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
      write_ne32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_ARM_ABS32:
      write_ne32 (dso, rela->r_offset, value + rela->r_addend);
      break;
    case R_ARM_PC24:
      val = value + rela->r_addend - rela->r_offset;
      val >>= 2;
      if ((Elf32_Word) val + 0x800000 >= 0x1000000)
	{
	  error (0, 0, "%s: R_ARM_PC24 overflow", dso->filename);
	  return 1;
	}
      val &= 0xffffff;
      write_ne32 (dso, rela->r_offset,
		  (read_une32 (dso, rela->r_offset) & 0xff000000) | val);
      break;
    case R_ARM_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_ARM_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown arm relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
arm_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
    case R_ARM_ABS32:
      buf_write_ne32 (info->dso, buf, rela->r_addend);
      break;
    default:
      abort ();
    }
  return 0;
}

static int
arm_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  GElf_Addr value;
  Elf32_Sword val;

  value = info->resolve (info, GELF_R_SYM (rel->r_info),
			 GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_NONE:
      break;
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
      buf_write_ne32 (info->dso, buf, value);
      break;
    case R_ARM_ABS32:
      buf_write_ne32 (info->dso, buf, value + read_une32 (info->dso, rel->r_offset));
      break;
    case R_ARM_PC24:
      val = value + rel->r_offset;
      value = read_une32 (info->dso, rel->r_offset) << 8;
      value = ((Elf32_Sword) value) >> 6;
      val += value;
      val >>= 2;
      if ((Elf32_Word) val + 0x800000 >= 0x1000000)
	{
	  error (0, 0, "%s: R_ARM_PC24 overflow", info->dso->filename);
	  return 1;
	}
      val &= 0xffffff;
      buf_write_ne32 (info->dso, buf, (buf_read_une32 (info->dso, buf) & 0xff000000) | val);
      break;
    case R_ARM_COPY:
      abort ();
    case R_ARM_RELATIVE:
      error (0, 0, "%s: R_ARM_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
arm_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;
  Elf32_Sword val;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ARM_NONE:
      break;
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
    case R_ARM_ABS32:
      buf_write_ne32 (info->dso, buf, value + rela->r_addend);
      break;
    case R_ARM_PC24:
      val = value + rela->r_addend - rela->r_offset;
      val >>= 2;
      if ((Elf32_Word) val + 0x800000 >= 0x1000000)
	{
	  error (0, 0, "%s: R_ARM_PC24 overflow", info->dso->filename);
	  return 1;
	}
      val &= 0xffffff;
      buf_write_ne32 (info->dso, buf, (buf_read_une32 (info->dso, buf) & 0xff000000) | val);
      break;
    case R_ARM_COPY:
      abort ();
    case R_ARM_RELATIVE:
      error (0, 0, "%s: R_ARM_RELATIVE in ET_EXEC object?", info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
arm_prelink_conflict_rel (DSO *dso, struct prelink_info *info, GElf_Rel *rel,
			   GElf_Addr reladdr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;

  if (GELF_R_TYPE (rel->r_info) == R_ARM_RELATIVE
      || GELF_R_TYPE (rel->r_info) == R_ARM_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rel->r_info),
			       GELF_R_TYPE (rel->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict_lookup_value (conflict);
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rel->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rel->r_info));
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
      ret->r_addend = (Elf32_Sword) value;
      break;
    case R_ARM_ABS32:
    case R_ARM_PC24:
      error (0, 0, "%s: R_ARM_%s relocs should not be present in prelinked REL sections",
	     dso->filename, GELF_R_TYPE (rel->r_info) == R_ARM_ABS32 ? "ABS32" : "PC24");
      return 1;
    case R_ARM_COPY:
      error (0, 0, "R_ARM_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown arm relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
arm_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *ret;
  Elf32_Sword val;

  if (GELF_R_TYPE (rela->r_info) == R_ARM_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_ARM_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    return 0;
  value = conflict_lookup_value (conflict);
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  ret->r_info = GELF_R_INFO (0, GELF_R_TYPE (rela->r_info));
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_ARM_GLOB_DAT:
    case R_ARM_JUMP_SLOT:
    case R_ARM_ABS32:
      ret->r_addend = (Elf32_Sword) (value + rela->r_addend);
      break;
    case R_ARM_PC24:
      val = value + rela->r_addend - rela->r_offset;
      val >>= 2;
      if ((Elf32_Word) val + 0x800000 >= 0x1000000)
	{
	  error (0, 0, "%s: R_ARM_PC24 overflow", dso->filename);
	  return 1;
	}
      value = read_une32 (dso, rela->r_offset) & 0xff000000;
      ret->r_addend = (Elf32_Sword) (value | (val & 0xffffff));
      ret->r_info = GELF_R_INFO (0, R_ARM_ABS32);
      break;
    case R_ARM_COPY:
      error (0, 0, "R_ARM_COPY should not be present in shared libraries");
      return 1;
    default:
      error (0, 0, "%s: Unknown arm relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
arm_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  rela->r_offset = rel->r_offset;
  rela->r_info = rel->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_JUMP_SLOT:
      /* We should be never converting .rel.plt into .rela.plt.  */
      abort ();
    case R_ARM_RELATIVE:
    case R_ARM_ABS32:
      rela->r_addend = (Elf32_Sword) read_une32 (dso, rel->r_offset);
      break;
    case R_ARM_PC24:
      rela->r_addend = read_une32 (dso, rel->r_offset) << 8;
      rela->r_addend = ((Elf32_Sword) rela->r_addend) >> 6;
      break;
    case R_ARM_COPY:
    case R_ARM_GLOB_DAT:
      rela->r_addend = 0;
      break;
    }
  return 0;
}

static int
arm_rela_to_rel (DSO *dso, GElf_Rela *rela, GElf_Rel *rel)
{
  rel->r_offset = rela->r_offset;
  rel->r_info = rela->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_JUMP_SLOT:
      /* We should be never converting .rel.plt into .rela.plt
	 and thus never .rela.plt back to .rel.plt.  */
      abort ();
    case R_ARM_RELATIVE:
    case R_ARM_ABS32:
      write_ne32 (dso, rela->r_offset, rela->r_addend);
      break;
    case R_ARM_PC24:
      write_ne32 (dso, rela->r_offset,
		  (read_une32 (dso, rela->r_offset) & 0xff000000)
		  | ((rela->r_addend >> 2) & 0xffffff));
      break;
    case R_ARM_GLOB_DAT:
      write_ne32 (dso, rela->r_offset, 0);
      break;
    }
  return 0;
}

static int
arm_need_rel_to_rela (DSO *dso, int first, int last)
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
	      case R_ARM_ABS32:
		val = read_une32 (dso, rel->r_offset);
		/* R_ARM_ABS32 with addend 0 can be converted
		   to R_ARM_GLOB_DAT and we don't have to convert
		   to RELA because of that.  */
		if (val == 0)
		  break;
		/* FALLTHROUGH */
	      case R_ARM_PC24:
		return 1;
	      }
	}
    }
  return 0;
}

static int
arm_arch_prelink (struct prelink_info *info)
{
  DSO *dso;
  int i;

  dso = info->dso;
  if (dso->info[DT_PLTGOT])
    {
      /* Write address of .plt into got[1].
	 .plt is what got[3] contains unless prelinking.  */
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
      data = dso->shdr[i].sh_addr;
      write_ne32 (dso, dso->info[DT_PLTGOT] + 4, data);
    }

  return 0;
}

static int
arm_arch_undo_prelink (DSO *dso)
{
  int i;

  if (dso->info[DT_PLTGOT])
    {
      /* Clear got[1] if it contains address of .plt.  */
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
      if (data == dso->shdr[i].sh_addr)
	write_ne32 (dso, dso->info[DT_PLTGOT] + 4, 0);
    }

  return 0;
}

static int
arm_undo_prelink_rel (DSO *dso, GElf_Rel *rel, GElf_Addr reladdr)
{
  int sec;
  const char *name;

  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_ARM_RELATIVE:
    case R_ARM_NONE:
      break;
    case R_ARM_JUMP_SLOT:
      sec = addr_to_sec (dso, rel->r_offset);
      name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[sec].sh_name);
      if (sec == -1 || (strcmp (name, ".got") && strcmp (name, ".got.plt")))
	{
	  error (0, 0, "%s: R_ARM_JMP_SLOT not pointing into .got section",
		 dso->filename);
	  return 1;
	}
      else
	{
	  Elf32_Addr data = read_une32 (dso, dso->shdr[sec].sh_addr + 4);

	  assert (rel->r_offset >= dso->shdr[sec].sh_addr + 12);
	  assert (((rel->r_offset - dso->shdr[sec].sh_addr) & 3) == 0);
	  write_ne32 (dso, rel->r_offset, data);
	}
      break;
    case R_ARM_GLOB_DAT:
      sec = addr_to_sec (dso, rel->r_offset);

      write_ne32 (dso, rel->r_offset, 0);
      if (sec != -1)
	{
	  if (strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			      dso->shdr[sec].sh_name),
		      ".got"))
	    {
	      rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_ARM_ABS32);
	      return 2;
	    }
	}
      break;
    case R_ARM_ABS32:
    case R_ARM_PC24:
      error (0, 0, "%s: R_ARM_%s relocs should not be present in prelinked REL sections",
	     GELF_R_TYPE (rel->r_info) == R_ARM_ABS32 ? "ABS32" : "PC24",
	     dso->filename);
      return 1;
    case R_ARM_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_ARM_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown arm relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
arm_reloc_size (int reloc_type)
{
  assert (reloc_type != R_ARM_COPY);
  return 4;
}

static int
arm_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_ARM_COPY: return RTYPE_CLASS_COPY;
    case R_ARM_JUMP_SLOT: return RTYPE_CLASS_PLT;
    default: return RTYPE_CLASS_VALID;
    }
}

PL_ARCH = {
  .name = "ARM",
  .class = ELFCLASS32,
  .machine = EM_ARM,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_ARM_JUMP_SLOT,
  .R_COPY = R_ARM_COPY,
  .R_RELATIVE = R_ARM_RELATIVE,
  .dynamic_linker = "/lib/ld-linux.so.2",
  .adjust_dyn = arm_adjust_dyn,
  .adjust_rel = arm_adjust_rel,
  .adjust_rela = arm_adjust_rela,
  .prelink_rel = arm_prelink_rel,
  .prelink_rela = arm_prelink_rela,
  .prelink_conflict_rel = arm_prelink_conflict_rel,
  .prelink_conflict_rela = arm_prelink_conflict_rela,
  .apply_conflict_rela = arm_apply_conflict_rela,
  .apply_rel = arm_apply_rel,
  .apply_rela = arm_apply_rela,
  .rel_to_rela = arm_rel_to_rela,
  .rela_to_rel = arm_rela_to_rel,
  .need_rel_to_rela = arm_need_rel_to_rela,
  .reloc_size = arm_reloc_size,
  .reloc_class = arm_reloc_class,
  .max_reloc_size = 4,
  .arch_prelink = arm_arch_prelink,
  .arch_undo_prelink = arm_arch_undo_prelink,
  .undo_prelink_rel = arm_undo_prelink_rel,
  /* Although TASK_UNMAPPED_BASE is 0x40000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x41000000,
  .mmap_end =  0x50000000,
  .max_page_size = 0x8000,
  .page_size = 0x1000
};
