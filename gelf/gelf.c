/* Generic ELF wrapper for libelf which does not support gelf_ API.
   Copyright (C) 2001, 2002, 2004 Red Hat, Inc.
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
#include <elf.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "gelf.h"

inline int
gelf_getclass (Elf *elf)
{
  size_t size;
  char *e_ident = elf_getident (elf, &size);

  if (e_ident == NULL)
    return ELFCLASSNONE;
  switch (e_ident [EI_CLASS])
    {
    case ELFCLASS32:
    case ELFCLASS64:
      return e_ident [EI_CLASS];
    default:
      return ELFCLASSNONE;
    }
}

size_t
gelf_fsize (Elf *elf, Elf_Type type, size_t count, unsigned int ver)
{
  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      return elf32_fsize (type, count, ver);
    case ELFCLASS64:
      return elf64_fsize (type, count, ver);
    default:
      return 0;
    }
}

GElf_Ehdr *
gelf_getehdr (Elf *elf, GElf_Ehdr *dst)
{
  Elf32_Ehdr *ehdr32;
  Elf64_Ehdr *ehdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      ehdr32 = elf32_getehdr (elf);
      if (ehdr32 != NULL)
	{
	  memcpy (dst->e_ident, ehdr32->e_ident, EI_NIDENT);
	  dst->e_type = ehdr32->e_type;
	  dst->e_machine = ehdr32->e_machine;
	  dst->e_version = ehdr32->e_version;
	  dst->e_entry = ehdr32->e_entry;
	  dst->e_phoff = ehdr32->e_phoff;
	  dst->e_shoff = ehdr32->e_shoff;
	  dst->e_flags = ehdr32->e_flags;
	  dst->e_ehsize = ehdr32->e_ehsize;
	  dst->e_phentsize = ehdr32->e_phentsize;
	  dst->e_phnum = ehdr32->e_phnum;
	  dst->e_shentsize = ehdr32->e_shentsize;
	  dst->e_shnum = ehdr32->e_shnum;
	  dst->e_shstrndx = ehdr32->e_shstrndx;
	  return dst;
	}
      break;
    case ELFCLASS64:
      ehdr64 = elf64_getehdr (elf);
      if (ehdr64 != NULL)
	{
	  memcpy (dst, ehdr64, sizeof (Elf64_Ehdr));
	  return dst;
	}
    }
  return NULL;
}

int
gelf_update_ehdr (Elf *elf, GElf_Ehdr *src)
{
  Elf32_Ehdr *ehdr32;
  Elf64_Ehdr *ehdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      ehdr32 = elf32_getehdr (elf);
      if (ehdr32 == NULL)
	return 0;
      memcpy (ehdr32->e_ident, src->e_ident, EI_NIDENT);
      ehdr32->e_type = src->e_type;
      ehdr32->e_machine = src->e_machine;
      ehdr32->e_version = src->e_version;
      ehdr32->e_entry = src->e_entry;
      ehdr32->e_phoff = src->e_phoff;
      ehdr32->e_shoff = src->e_shoff;
      ehdr32->e_flags = src->e_flags;
      ehdr32->e_ehsize = src->e_ehsize;
      ehdr32->e_phentsize = src->e_phentsize;
      ehdr32->e_phnum = src->e_phnum;
      ehdr32->e_shentsize = src->e_shentsize;
      ehdr32->e_shnum = src->e_shnum;
      ehdr32->e_shstrndx = src->e_shstrndx;
      return 1;
    case ELFCLASS64:
      ehdr64 = elf64_getehdr (elf);
      if (ehdr64 != NULL)
	{
	  memcpy (ehdr64, src, sizeof (Elf64_Ehdr));
	  return 1;
	}
    default:
      break;
    }
  return 0;
}

unsigned long
gelf_newehdr (Elf *elf, int class)
{
  switch (class)
    {
    case ELFCLASS32:
      return (unsigned long) elf32_newehdr (elf);
    case ELFCLASS64:
      return (unsigned long) elf64_newehdr (elf);
    default:
      return 0;
    }
}

GElf_Phdr *
gelf_getphdr (Elf *elf, int ndx, GElf_Phdr *dst)
{
  Elf32_Ehdr *ehdr32;
  Elf64_Ehdr *ehdr64;
  Elf32_Phdr *phdr32;
  Elf64_Phdr *phdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      phdr32 = elf32_getphdr (elf);
      if (phdr32 == NULL)
	return NULL;
      ehdr32 = elf32_getehdr (elf);
      if (ehdr32 == NULL)
	return NULL;
      if (ndx >= ehdr32->e_phnum)
	return NULL;
      phdr32 += ndx;
      dst->p_type = phdr32->p_type;
      dst->p_offset = phdr32->p_offset;
      dst->p_vaddr = phdr32->p_vaddr;
      dst->p_paddr = phdr32->p_paddr;
      dst->p_filesz = phdr32->p_filesz;
      dst->p_memsz = phdr32->p_memsz;
      dst->p_flags = phdr32->p_flags;
      dst->p_align = phdr32->p_align;
      return dst;
    case ELFCLASS64:
      phdr64 = elf64_getphdr (elf);
      if (phdr64 == NULL)
	return NULL;
      ehdr64 = elf64_getehdr (elf);
      if (ehdr64 == NULL)
	return NULL;
      if (ndx >= ehdr64->e_phnum)
	return NULL;
      memcpy (dst, phdr64 + ndx, sizeof (Elf64_Phdr));
      return dst;
    default:
      return NULL;
    }
}

int
gelf_update_phdr (Elf *elf, int ndx, GElf_Phdr *src)
{
  Elf32_Ehdr *ehdr32;
  Elf64_Ehdr *ehdr64;
  Elf32_Phdr *phdr32;
  Elf64_Phdr *phdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      phdr32 = elf32_getphdr (elf);
      if (phdr32 == NULL)
	return 0;
      ehdr32 = elf32_getehdr (elf);
      if (ehdr32 == NULL)
	return 0;
      if (ndx >= ehdr32->e_phnum)
	return 0;
      phdr32 += ndx;
      phdr32->p_type = src->p_type;
      phdr32->p_offset = src->p_offset;
      phdr32->p_vaddr = src->p_vaddr;
      phdr32->p_paddr = src->p_paddr;
      phdr32->p_filesz = src->p_filesz;
      phdr32->p_memsz = src->p_memsz;
      phdr32->p_flags = src->p_flags;
      phdr32->p_align = src->p_align;
      return 1;
    case ELFCLASS64:
      phdr64 = elf64_getphdr (elf);
      if (phdr64 == NULL)
	return 0;
      ehdr64 = elf64_getehdr (elf);
      if (ehdr64 == NULL)
	return 0;
      if (ndx >= ehdr64->e_phnum)
	return 0;
      memcpy (phdr64 + ndx, src, sizeof (Elf64_Phdr));
      return 1;
    default:
      return 0;
    }
}

unsigned long
gelf_newphdr (Elf *elf, size_t phnum)
{
  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      return (unsigned long) elf32_newphdr (elf, phnum);
    case ELFCLASS64:
      return (unsigned long) elf64_newphdr (elf, phnum);
    default:
      return 0;
    }
}

GElf_Shdr *
gelfx_getshdr (Elf *elf, Elf_Scn *scn, GElf_Shdr *dst)
{
  Elf32_Shdr *shdr32;
  Elf64_Shdr *shdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      shdr32 = elf32_getshdr (scn);
      if (shdr32 == NULL)
	return NULL;
      dst->sh_name = shdr32->sh_name;
      dst->sh_type = shdr32->sh_type;
      dst->sh_flags = shdr32->sh_flags;
      dst->sh_addr = shdr32->sh_addr;
      dst->sh_offset = shdr32->sh_offset;
      dst->sh_size = shdr32->sh_size;
      dst->sh_link = shdr32->sh_link;
      dst->sh_info = shdr32->sh_info;
      dst->sh_addralign = shdr32->sh_addralign;
      dst->sh_entsize = shdr32->sh_entsize;
      return dst;
    case ELFCLASS64:
      shdr64 = elf64_getshdr (scn);
      if (shdr64 == NULL)
	return NULL;
      memcpy (dst, shdr64, sizeof (Elf64_Shdr));
      return dst;
    default:
      return NULL;
    }
}

int
gelfx_update_shdr (Elf *elf, Elf_Scn *scn, GElf_Shdr *src)
{
  Elf32_Shdr *shdr32;
  Elf64_Shdr *shdr64;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      shdr32 = elf32_getshdr (scn);
      if (shdr32 == NULL)
	return 0;
      shdr32->sh_name = src->sh_name;
      shdr32->sh_type = src->sh_type;
      shdr32->sh_flags = src->sh_flags;
      shdr32->sh_addr = src->sh_addr;
      shdr32->sh_offset = src->sh_offset;
      shdr32->sh_size = src->sh_size;
      shdr32->sh_link = src->sh_link;
      shdr32->sh_info = src->sh_info;
      shdr32->sh_addralign = src->sh_addralign;
      shdr32->sh_entsize = src->sh_entsize;
      return 1;
    case ELFCLASS64:
      shdr64 = elf64_getshdr (scn);
      if (shdr64 == NULL)
	return 0;
      memcpy (shdr64, src, sizeof (Elf64_Shdr));
      return 1;
    default:
      return 0;
    }
}

Elf_Data *
gelf_xlatetom (Elf *elf, Elf_Data *dst, const Elf_Data *src, unsigned encode)
{
  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      return elf32_xlatetom (dst, src, encode);
    case ELFCLASS64:
      return elf64_xlatetom (dst, src, encode);
    default:
      return NULL;
    }
}

Elf_Data *
gelf_xlatetof (Elf *elf, Elf_Data *dst, const Elf_Data *src, unsigned encode)
{
  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      return elf32_xlatetof (dst, src, encode);
    case ELFCLASS64:
      return elf64_xlatetof (dst, src, encode);
    default:
      return NULL;
    }
}

GElf_Sym *gelfx_getsym (Elf *elf, Elf_Data *data, int ndx, GElf_Sym *dst)
{
  Elf32_Sym *sym32;

  if (data->d_type != ELF_T_SYM)
    return NULL;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Sym) > data->d_size)
	return NULL;
      sym32 = &((Elf32_Sym *) data->d_buf)[ndx];
      dst->st_name = sym32->st_name;
      dst->st_info = sym32->st_info;
      dst->st_other = sym32->st_other;
      dst->st_shndx = sym32->st_shndx;
      dst->st_value = sym32->st_value;
      dst->st_size = sym32->st_size;
      return dst;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Sym) > data->d_size)
	return NULL;
      *dst = ((GElf_Sym *) data->d_buf)[ndx];
      return dst;
    default:
      return NULL;
    }
}

int gelfx_update_sym (Elf *elf, Elf_Data *data, int ndx, GElf_Sym *src)
{
  Elf32_Sym *sym32;

  if (data->d_type != ELF_T_SYM)
    return 0;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Sym) > data->d_size)
	return 0;
      sym32 = &((Elf32_Sym *) data->d_buf)[ndx];
      sym32->st_name = src->st_name;
      sym32->st_info = src->st_info;
      sym32->st_other = src->st_other;
      sym32->st_shndx = src->st_shndx;
      sym32->st_value = src->st_value;
      sym32->st_size = src->st_size;
      return 1;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Sym) > data->d_size)
	return 0;
      ((GElf_Sym *) data->d_buf)[ndx] = *src;
      return 1;
    default:
      return 0;
    }
}

GElf_Dyn *gelfx_getdyn (Elf *elf, Elf_Data *data, int ndx, GElf_Dyn *dst)
{
  Elf32_Dyn *dyn32;

  if (data->d_type != ELF_T_DYN)
    return NULL;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Dyn) > data->d_size)
	return NULL;
      dyn32 = &((Elf32_Dyn *) data->d_buf)[ndx];
      dst->d_tag = dyn32->d_tag;
      dst->d_un.d_val = dyn32->d_un.d_val;
      return dst;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Dyn) > data->d_size)
	return NULL;
      *dst = ((GElf_Dyn *) data->d_buf)[ndx];
      return dst;
    default:
      return NULL;
    }
}

int gelfx_update_dyn (Elf *elf, Elf_Data *data, int ndx, GElf_Dyn *src)
{
  Elf32_Dyn *dyn32;

  if (data->d_type != ELF_T_DYN)
    return 0;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Dyn) > data->d_size)
	return 0;
      dyn32 = &((Elf32_Dyn *) data->d_buf)[ndx];
      dyn32->d_tag = src->d_tag;
      dyn32->d_un.d_val = src->d_un.d_val;
      return 1;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Dyn) > data->d_size)
	return 0;
      ((GElf_Dyn *) data->d_buf)[ndx] = *src;
      return 1;
    default:
      return 0;
    }
}

GElf_Rel *gelfx_getrel (Elf *elf, Elf_Data *data, int ndx, GElf_Rel *dst)
{
  Elf32_Rel *rel32;

  if (data->d_type != ELF_T_REL)
    return NULL;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Rel) > data->d_size)
	return NULL;
      rel32 = &((Elf32_Rel *) data->d_buf)[ndx];
      dst->r_offset = rel32->r_offset;
      dst->r_info = GELF_R_INFO (ELF32_R_SYM (rel32->r_info),
				 ELF32_R_TYPE (rel32->r_info));
      return dst;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Rel) > data->d_size)
	return NULL;
      *dst = ((GElf_Rel *) data->d_buf)[ndx];
      return dst;
    default:
      return NULL;
    }
}

int gelfx_update_rel (Elf *elf, Elf_Data *data, int ndx, GElf_Rel *src)
{
  Elf32_Rel *rel32;

  if (data->d_type != ELF_T_REL)
    return 0;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Rel) > data->d_size)
	return 0;
      rel32 = &((Elf32_Rel *) data->d_buf)[ndx];
      rel32->r_offset = src->r_offset;
      rel32->r_info = ELF32_R_INFO (GELF_R_SYM (src->r_info),
				     GELF_R_TYPE (src->r_info));
      return 1;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Rel) > data->d_size)
	return 0;
      ((GElf_Rel *) data->d_buf)[ndx] = *src;
      return 1;
    default:
      return 0;
    }
}

GElf_Rela *gelfx_getrela (Elf *elf, Elf_Data *data, int ndx, GElf_Rela *dst)
{
  Elf32_Rela *rela32;

  if (data->d_type != ELF_T_RELA)
    return NULL;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Rela) > data->d_size)
	return NULL;
      rela32 = &((Elf32_Rela *) data->d_buf)[ndx];
      dst->r_offset = rela32->r_offset;
      dst->r_info = GELF_R_INFO (ELF32_R_SYM (rela32->r_info),
				 ELF32_R_TYPE (rela32->r_info));
      dst->r_addend = rela32->r_addend;
      return dst;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Rela) > data->d_size)
	return NULL;
      *dst = ((GElf_Rela *) data->d_buf)[ndx];
      return dst;
    default:
      return NULL;
    }
}

int gelfx_update_rela (Elf *elf, Elf_Data *data, int ndx, GElf_Rela *src)
{
  Elf32_Rela *rela32;

  if (data->d_type != ELF_T_RELA)
    return 0;

  switch (gelf_getclass (elf))
    {
    case ELFCLASS32:
      if ((ndx + 1) * sizeof (Elf32_Rela) > data->d_size)
	return 0;
      rela32 = &((Elf32_Rela *) data->d_buf)[ndx];
      rela32->r_offset = src->r_offset;
      rela32->r_info = ELF32_R_INFO (GELF_R_SYM (src->r_info),
				     GELF_R_TYPE (src->r_info));
      rela32->r_addend = src->r_addend;
      return 1;
    case ELFCLASS64:
      if ((ndx + 1) * sizeof (Elf64_Rela) > data->d_size)
	return 0;
      ((GElf_Rela *) data->d_buf)[ndx] = *src;
      return 1;
    default:
      return 0;
    }
}
