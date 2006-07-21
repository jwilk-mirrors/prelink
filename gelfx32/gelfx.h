/* gelf API which supports ELFCLASS32 only.
   Copyright (C) 2001 Red Hat, Inc.
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

#ifndef GELFX_H
#define	GELFX_H

#include <error.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>

typedef Elf32_Half	GElf_Half;
typedef Elf32_Word	GElf_Word;
typedef	Elf32_Sword	GElf_Sword;
typedef Elf32_Xword	GElf_Xword;
typedef	Elf32_Sxword	GElf_Sxword;
typedef Elf32_Addr	GElf_Addr;
typedef Elf32_Off	GElf_Off;
typedef Elf32_Ehdr	GElf_Ehdr;
typedef Elf32_Shdr	GElf_Shdr;
typedef Elf32_Section	GElf_Section;
typedef Elf32_Sym	GElf_Sym;
typedef Elf32_Rel	GElf_Rel;
typedef Elf32_Rela	GElf_Rela;
typedef Elf32_Phdr	GElf_Phdr;
typedef Elf32_Dyn	GElf_Dyn;
#define GELF_ST_BIND	ELF32_ST_BIND
#define GELF_ST_TYPE	ELF32_ST_TYPE
#define GELF_ST_INFO	ELF32_ST_INFO
#define GELF_R_SYM	ELF32_R_SYM
#define GELF_R_TYPE	ELF32_R_TYPE
#define GELF_R_INFO	ELF32_R_INFO

extern inline int
gelf_getclass (Elf *elf)
{
  size_t size;
  char *e_ident = elf_getident (elf, &size);
  if (e_ident [EI_CLASS] == ELFCLASS64)
    error (EXIT_FAILURE, 0, "64-bit ELF not supported");
  return e_ident [EI_CLASS] == ELFCLASS32 ? ELFCLASS32 : ELFCLASSNONE;
}

#define gelf_fsize(e,t,c,v) elf32_fsize(t,c,v)

extern inline GElf_Ehdr *gelf_getehdr (Elf *elf, GElf_Ehdr *dst)
{
  Elf32_Ehdr *ehdr = elf32_getehdr (elf);
  if (ehdr == NULL)
    return NULL;
  return memcpy (dst, ehdr, sizeof (Elf32_Ehdr));
}

extern inline int
gelf_update_ehdr (Elf *elf, GElf_Ehdr *src)
{
  Elf32_Ehdr *ehdr = elf32_getehdr (elf);
  if (ehdr == NULL)
    return 0;
  memcpy (ehdr, src, sizeof (Elf32_Ehdr));
  return 1;
}

extern inline unsigned long
gelf_newehdr (Elf *elf, int class)
{
  if (class != ELFCLASS32)
    return 0;
  return (unsigned long) elf32_newehdr (elf);
}

extern inline GElf_Phdr *
gelf_getphdr (Elf *elf, int ndx, GElf_Phdr *dst)
{
  Elf32_Ehdr *ehdr = elf32_getehdr (elf);
  Elf32_Phdr *phdr = elf32_getphdr (elf);
  if (ehdr == NULL || phdr == NULL || ndx >= ehdr->e_phnum)
    return NULL;
  return memcpy (dst, phdr + ndx, sizeof (Elf32_Phdr));
}

extern inline int
gelf_update_phdr (Elf *elf, int ndx, GElf_Phdr *src)
{
  Elf32_Ehdr *ehdr = elf32_getehdr (elf);
  Elf32_Phdr *phdr = elf32_getphdr (elf);
  if (ehdr == NULL || phdr == NULL || ndx >= ehdr->e_phnum)
    return 0;
  memcpy (phdr + ndx, src, sizeof (Elf32_Phdr));
  return 1;
}

extern inline unsigned long
gelf_newphdr (Elf *elf, size_t phnum)
{
  return (unsigned long) elf32_newphdr (elf, phnum);
}

#define gelf_xlatetom(e,d,s,n) elf32_xlatetom(e,d,s,n)
#define gelf_xlatetof(e,d,s,n) elf32_xlatetof(e,d,s,n)

extern inline GElf_Shdr *
gelf_getshdr (Elf_Scn *scn, GElf_Shdr *dst)
{
  Elf32_Shdr *shdr = elf32_getshdr (scn);
  if (shdr == NULL)
    return NULL;
  return memcpy (dst, shdr, sizeof (Elf32_Shdr));
}

extern inline int
gelf_update_shdr (Elf_Scn *scn, GElf_Shdr *src)
{
  Elf32_Shdr *shdr = elf32_getshdr (scn);
  if (shdr == NULL)
    return 0;
  memcpy (shdr, src, sizeof (Elf32_Shdr));
  return 1;
}

extern inline GElf_Sym *
gelf_getsym (Elf_Data *data, int ndx, GElf_Sym *dst)
{
  if (data->d_type != ELF_T_SYM
      || (ndx + 1) * sizeof (Elf32_Sym) > data->d_size)
    return NULL;
  *dst = ((GElf_Sym *) data->d_buf)[ndx];
  return dst;
}

extern inline int
gelf_update_sym (Elf_Data *data, int ndx, GElf_Sym *src)
{
  if (data->d_type != ELF_T_SYM
      || (ndx + 1) * sizeof (Elf32_Sym) > data->d_size)
    return 0;
  ((GElf_Sym *) data->d_buf)[ndx] = *src;
  return 1;
}

extern inline GElf_Dyn *
gelf_getdyn (Elf_Data *data, int ndx, GElf_Dyn *dst)
{
  if (data->d_type != ELF_T_DYN
      || (ndx + 1) * sizeof (Elf32_Dyn) > data->d_size)
    return NULL;
  *dst = ((GElf_Dyn *) data->d_buf)[ndx];
  return dst;
}

extern inline int
gelf_update_dyn (Elf_Data *data, int ndx, GElf_Dyn *src)
{
  if (data->d_type != ELF_T_DYN
      || (ndx + 1) * sizeof (Elf32_Dyn) > data->d_size)
    return 0;
  ((GElf_Dyn *) data->d_buf)[ndx] = *src;
  return 1;
}

extern inline GElf_Rel *
gelf_getrel (Elf_Data *data, int ndx, GElf_Rel *dst)
{
  if (data->d_type != ELF_T_REL
      || (ndx + 1) * sizeof (Elf32_Rel) > data->d_size)
    return NULL;
  *dst = ((GElf_Rel *) data->d_buf)[ndx];
  return dst;
}

extern inline int
gelf_update_rel (Elf_Data *data, int ndx, GElf_Rel *src)
{
  if (data->d_type != ELF_T_REL
      || (ndx + 1) * sizeof (Elf32_Rel) > data->d_size)
    return 0;
  ((GElf_Rel *) data->d_buf)[ndx] = *src;
  return 1;
}

extern inline GElf_Rela *
gelf_getrela (Elf_Data *data, int ndx, GElf_Rela *dst)
{
  if (data->d_type != ELF_T_RELA
      || (ndx + 1) * sizeof (Elf32_Rela) > data->d_size)
    return NULL;
  *dst = ((GElf_Rela *) data->d_buf)[ndx];
  return dst;
}

extern inline int
gelf_update_rela (Elf_Data *data, int ndx, GElf_Rela *src)
{
  if (data->d_type != ELF_T_RELA
      || (ndx + 1) * sizeof (Elf32_Rela) > data->d_size)
    return 0;
  ((GElf_Rela *) data->d_buf)[ndx] = *src;
  return 1;
}

#define gelfx_getshdr(elf,scn,shdr) gelf_getshdr(scn,shdr)
#define gelfx_update_shdr(elf,scn,shdr) gelf_update_shdr(scn,shdr)
#define gelfx_getsym(elf,data,ndx,x) gelf_getsym(data,ndx,x)
#define gelfx_update_sym(elf,data,ndx,x) gelf_update_sym(data,ndx,x)
#define gelfx_getdyn(elf,data,ndx,x) gelf_getdyn(data,ndx,x)
#define gelfx_update_dyn(elf,data,ndx,x) gelf_update_dyn(data,ndx,x)
#define gelfx_getrel(elf,data,ndx,x) gelf_getrel(data,ndx,x)
#define gelfx_update_rel(elf,data,ndx,x) gelf_update_rel(data,ndx,x)
#define gelfx_getrela(elf,data,ndx,x) gelf_getrela(data,ndx,x)
#define gelfx_update_rela(elf,data,ndx,x) gelf_update_rela(data,ndx,x)

#endif	/* GELFX_H */
