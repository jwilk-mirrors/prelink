/* Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006 Red Hat, Inc.
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
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "prelink.h"
#include "reloc.h"

static GElf_Addr
resolve_ldso (struct prelink_info *info, GElf_Word r_sym,
	      int reloc_type __attribute__((unused)))
{
  /* Dynamic linker does not depend on any other library,
     all symbols resolve to themselves with the exception
     of SHN_UNDEF symbols which resolve to 0.  */
  if (info->symtab[r_sym].st_shndx == SHN_UNDEF)
    {
      info->resolveent = NULL;
      info->resolvetls = NULL;
      return 0;
    }
  else
    {
      /* As the dynamic linker is relocated first,
	 l_addr will be 0.  */
      info->resolveent = info->ent;
      info->resolvetls = NULL;
      return 0 + info->symtab[r_sym].st_value;
    }
}

static GElf_Addr
resolve_dso (struct prelink_info *info, GElf_Word r_sym,
	     int reloc_type)
{
  struct prelink_symbol *s;
  int reloc_class = info->dso->arch->reloc_class (reloc_type);

  for (s = & info->symbols[r_sym]; s; s = s->next)
    if (s->reloc_class == reloc_class)
      break;

  info->resolveent = NULL;
  info->resolvetls = NULL;

  if (s == NULL || s->u.ent == NULL)
    return 0;

  if (reloc_class == RTYPE_CLASS_TLS)
    {
      info->resolvetls = s->u.tls;
      return s->value;
    }

  info->resolveent = s->u.ent;
  return s->u.ent->base + s->value;
}

static int
prelink_rel (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rel rel;
  int sec;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  switch (dso->arch->prelink_rel (info, &rel, addr))
	    {
	    case 2:
	      gelfx_update_rel (dso->elf, data, ndx, &rel);
	      break;
	    case 0:
	      break;
	    default:
	      return 1;
	    }
	}
    }
  return 0;
}

static int
prelink_rela (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rela rela;
  int sec;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  switch (dso->arch->prelink_rela (info, &rela, addr))
	    {
	    case 2:
	      gelfx_update_rela (dso->elf, data, ndx, &rela);
	      break;
	    case 0:
	      break;
	    default:
	      return 1;
	    }
	}
    }
  return 0;
}

int
prelink_prepare (DSO *dso)
{
  struct reloc_info rinfo;
  int liblist = 0, libstr = 0, newlibstr = 0, undo = 0, newundo = 0;
  int i;

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name
	= strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
      if (! strcmp (name, ".gnu.liblist"))
	liblist = i;
      else if (! strcmp (name, ".gnu.libstr"))
	libstr = i;
      else if (! strcmp (name, ".gnu.prelink_undo"))
	undo = i;
    }

  if (undo == 0)
    {
      Elf32_Shdr *shdr32;
      Elf64_Shdr *shdr64;
      Elf_Data src, dst;

      dso->undo.d_size = gelf_fsize (dso->elf, ELF_T_EHDR, 1, EV_CURRENT)
			 + gelf_fsize (dso->elf, ELF_T_PHDR,
				       dso->ehdr.e_phnum, EV_CURRENT)
			 + gelf_fsize (dso->elf, ELF_T_SHDR,
				       dso->ehdr.e_shnum - 1, EV_CURRENT);
      dso->undo.d_buf = malloc (dso->undo.d_size);
      if (dso->undo.d_buf == NULL)
	{
	  error (0, ENOMEM, "%s: Could not create .gnu.prelink_undo section",
		 dso->filename);
	  return 1;
	}
      dso->undo.d_type = ELF_T_BYTE;
      dso->undo.d_off = 0;
      dso->undo.d_align = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
      dso->undo.d_version = EV_CURRENT;
      src = dso->undo;
      src.d_type = ELF_T_EHDR;
      src.d_size = gelf_fsize (dso->elf, ELF_T_EHDR, 1, EV_CURRENT);
      dst = src;
      switch (gelf_getclass (dso->elf))
	{
	case ELFCLASS32:
	  src.d_buf = elf32_getehdr (dso->elf);
	  if (elf32_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	case ELFCLASS64:
	  src.d_buf = elf64_getehdr (dso->elf);
	  if (elf64_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	default:
	  return 1;
	}
      src.d_buf = dst.d_buf + src.d_size;
      src.d_type = ELF_T_PHDR;
      src.d_size = gelf_fsize (dso->elf, ELF_T_PHDR, dso->ehdr.e_phnum,
			       EV_CURRENT);
      dst = src;
      switch (gelf_getclass (dso->elf))
	{
	case ELFCLASS32:
	  src.d_buf = elf32_getphdr (dso->elf);
	  if (elf32_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	case ELFCLASS64:
	  src.d_buf = elf64_getphdr (dso->elf);
	  if (elf64_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	}
      src.d_buf = dst.d_buf + src.d_size;
      src.d_type = ELF_T_SHDR;
      src.d_size = gelf_fsize (dso->elf, ELF_T_SHDR,
			       dso->ehdr.e_shnum - 1, EV_CURRENT);
      dst = src;
      switch (gelf_getclass (dso->elf))
	{
	case ELFCLASS32:
	  shdr32 = (Elf32_Shdr *) src.d_buf;
	  /* Note: cannot use dso->scn[i] below, since we want to save the
	     original section order before non-alloced sections were
	     sorted by sh_offset.  */
	  for (i = 1; i < dso->ehdr.e_shnum; ++i)
	    shdr32[i - 1] = *elf32_getshdr (elf_getscn (dso->elf, i));
	  if (elf32_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	case ELFCLASS64:
	  shdr64 = (Elf64_Shdr *) src.d_buf;
	  /* Note: cannot use dso->scn[i] below, since we want to save the
	     original section order before non-alloced sections were
	     sorted by sh_offset.  */
	  for (i = 1; i < dso->ehdr.e_shnum; ++i)
	    shdr64[i - 1] = *elf64_getshdr (elf_getscn (dso->elf, i));
	  if (elf64_xlatetof (&dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
	    {
	      error (0, 0, "%s: Failed to create .gnu.prelink_undo section",
		     dso->filename);
	      return 1;
	    }
	  break;
	}
    }

  if (dso->ehdr.e_type != ET_DYN)
    return 0;

  if (find_reloc_sections (dso, &rinfo))
    return 1;

  if (is_ldso_soname (dso->soname))
    {
      liblist = -1;
      libstr = -1;
    }

  if (liblist && libstr && undo
      && ! rinfo.rel_to_rela && ! rinfo.rel_to_rela_plt)
      return 0;

  if (! liblist || ! libstr || ! undo)
    {
      struct section_move *move;

      move = init_section_move (dso);
      if (move == NULL)
	return 1;

      if (! liblist)
	{
	  liblist = move->old_to_new [dso->ehdr.e_shstrndx];
	  add_section (move, liblist);
	}
      else
	liblist = 0;

      if (! libstr)
	{
	  add_section (move, liblist + 1);
	  libstr = liblist + 1;
	  newlibstr = 1;
	}
      else if (libstr != -1)
	libstr = move->old_to_new[libstr];

      if (! undo)
	{
	  if (libstr == -1)
	    {
	      undo = move->old_to_new [dso->ehdr.e_shstrndx];
	      add_section (move, undo);
	    }
	  else
	    {
	      add_section (move, libstr + 1);
	      undo = libstr + 1;
	    }
	  newundo = 1;
	}
      else
	undo = move->old_to_new[undo];

      if (reopen_dso (dso, move, NULL))
	{
	  free (move);
	  return 1;
	}

      free (move);
      if (liblist)
	{
	  memset (&dso->shdr[liblist], 0, sizeof (GElf_Shdr));
	  dso->shdr[liblist].sh_name = shstrtabadd (dso, ".gnu.liblist");
	  if (dso->shdr[liblist].sh_name == 0)
	    return 1;
	  dso->shdr[liblist].sh_type = SHT_GNU_LIBLIST;
	  dso->shdr[liblist].sh_offset = dso->shdr[liblist - 1].sh_offset;
	  if (dso->shdr[liblist - 1].sh_type != SHT_NOBITS)
	    dso->shdr[liblist].sh_offset += dso->shdr[liblist - 1].sh_size;
	  dso->shdr[liblist].sh_link = libstr;
	  dso->shdr[liblist].sh_addralign = sizeof (GElf_Word);
	  dso->shdr[liblist].sh_entsize = sizeof (Elf32_Lib);
	}

      if (newlibstr)
	{
	  memset (&dso->shdr[libstr], 0, sizeof (GElf_Shdr));
	  dso->shdr[libstr].sh_name = shstrtabadd (dso, ".gnu.libstr");
	  if (dso->shdr[libstr].sh_name == 0)
	    return 1;
	  dso->shdr[libstr].sh_type = SHT_STRTAB;
	  dso->shdr[libstr].sh_offset = dso->shdr[libstr - 1].sh_offset;
	  if (dso->shdr[libstr - 1].sh_type != SHT_NOBITS)
	    dso->shdr[libstr].sh_offset += dso->shdr[libstr - 1].sh_size;
	  dso->shdr[libstr].sh_addralign = 1;
	}

      if (newundo)
	{
	  Elf_Scn *scn;
	  Elf_Data *data;
	  GElf_Addr newoffset;

	  memset (&dso->shdr[undo], 0, sizeof (GElf_Shdr));
	  dso->shdr[undo].sh_name = shstrtabadd (dso, ".gnu.prelink_undo");
	  if (dso->shdr[undo].sh_name == 0)
	    return 1;
	  dso->shdr[undo].sh_type = SHT_PROGBITS;
	  dso->shdr[undo].sh_offset = dso->shdr[undo - 1].sh_offset;
	  if (dso->shdr[undo - 1].sh_type != SHT_NOBITS)
	    dso->shdr[undo].sh_offset += dso->shdr[undo - 1].sh_size;
	  dso->shdr[undo].sh_addralign = dso->undo.d_align;
	  dso->shdr[undo].sh_entsize = 1;
	  dso->shdr[undo].sh_size = dso->undo.d_size;
	  newoffset = dso->shdr[undo].sh_offset + dso->undo.d_align - 1;
	  newoffset &= ~(dso->shdr[undo].sh_addralign - 1);
	  if (adjust_dso_nonalloc (dso, undo + 1, dso->shdr[undo].sh_offset,
				   dso->undo.d_size + newoffset
				   - dso->shdr[undo].sh_offset))
	    return 1;
	  dso->shdr[undo].sh_offset = newoffset;
	  scn = dso->scn[undo];
	  data = elf_getdata (scn, NULL);
	  assert (data != NULL && elf_getdata (scn, data) == NULL);
	  free (data->d_buf);
	  *data = dso->undo;
	  dso->undo.d_buf = NULL;
	}
    }
  else if (reopen_dso (dso, NULL, NULL))
    return 1;

  if (rinfo.rel_to_rela || rinfo.rel_to_rela_plt)
    {
      /* On REL architectures, we might need to convert some REL
	 relocations to RELA relocs.  */

      int safe = 1, align = 0, last;
      GElf_Addr start, adjust, adjust1, adjust2;

      for (i = 1; i < (rinfo.plt ? rinfo.plt : rinfo.first); i++)
	switch (dso->shdr[i].sh_type)
	  {
	  case SHT_HASH:
	  case SHT_GNU_HASH:
	  case SHT_DYNSYM:
	  case SHT_REL:
	  case SHT_RELA:
	  case SHT_STRTAB:
	  case SHT_NOTE:
	  case SHT_GNU_verdef:
	  case SHT_GNU_verneed:
	  case SHT_GNU_versym:
	    /* These sections are safe, no relocations should point
	       to it, therefore enlarging a section after sections
	       from this set only (and SHT_REL) in ET_DYN just needs
	       adjusting the rest of the library.  */
	    break;
	  case SHT_DYNAMIC:
	  case SHT_MIPS_REGINFO:
	    /* The same applies to these sections on MIPS.  The convention
	       is to put .dynamic and .reginfo near the beginning of the
	       read-only segment, before the program text.  No relocations
	       may refer to them.  */
	    if (dso->ehdr.e_machine == EM_MIPS)
	      break;
	    /* FALLTHROUGH */
	  default:
	    /* The rest of sections are not safe.  */
	    safe = 0;
	    break;
	  }

      if (! safe)
	{
	  error (0, 0, "%s: Cannot safely convert %s' section from REL to RELA",
		 dso->filename, strptr (dso, dso->ehdr.e_shstrndx,
					dso->shdr[rinfo.rel_to_rela
					? rinfo.first : rinfo.plt].sh_name));
	  return 1;
	}

      for (i = rinfo.plt ? rinfo.plt : rinfo.first; i < dso->ehdr.e_shnum; i++)
	{
	  if (dso->shdr[i].sh_addralign > align)
	    align = dso->shdr[i].sh_addralign;
	}

      if (rinfo.plt)
	start = dso->shdr[rinfo.plt].sh_addr + dso->shdr[rinfo.plt].sh_size;
      else
	start = dso->shdr[rinfo.last].sh_addr + dso->shdr[rinfo.last].sh_size;

      adjust1 = 0;
      adjust2 = 0;
      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      if (rinfo.rel_to_rela)
	{
	  for (i = rinfo.first; i <= rinfo.last; ++i)
	    {
	      GElf_Addr size = dso->shdr[i].sh_size / 2 * 3;
	      adjust1 += size - dso->shdr[i].sh_size;
	      if (convert_rel_to_rela (dso, i))
		return 1;
	    }
	}
      if (rinfo.rel_to_rela_plt)
	{
	  GElf_Addr size = dso->shdr[rinfo.plt].sh_size / 2 * 3;
	  adjust2 = size - dso->shdr[rinfo.plt].sh_size;
	  if (convert_rel_to_rela (dso, rinfo.plt))
	    return 1;
	}

      adjust = adjust1 + adjust2;

      /* Need to make sure that all the remaining sections are properly
	 aligned.  */
      if (align)
	adjust = (adjust + align - 1) & ~(align - 1);

      /* Need to make sure adjust doesn't cause different Phdr segments
	 to overlap on the same page.  */
      last = -1;
      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	if (dso->phdr[i].p_type == PT_LOAD
	    && dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz >= start)
	  {
	    if (last != -1
		&& (((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz - 1)
		     ^ dso->phdr[i].p_vaddr)
		    & ~(dso->arch->max_page_size - 1))
		&& !(((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz
		       + adjust - 1)
		      ^ (dso->phdr[i].p_vaddr + adjust))
		     & ~(dso->arch->max_page_size - 1)))
	      {
		if (align >= dso->arch->max_page_size)
		  {
		    error (0, 0, "%s: Cannot grow reloc sections", dso->filename);
		    return 1;
		  }
		adjust = (adjust + dso->arch->max_page_size - 1)
			 & ~(dso->arch->max_page_size - 1);
	      }
	    last = i;
	  }

      /* Adjust all addresses pointing into remaining sections.  */
      if (adjust_dso (dso, start - 1, adjust))
	return 1;

      if (rinfo.rel_to_rela)
	{
	  GElf_Addr adjust3 = 0;
	  for (i = rinfo.first; i <= rinfo.last; ++i)
	    {
	      GElf_Addr size = dso->shdr[i].sh_size / 2 * 3;

	      dso->shdr[i].sh_addr += adjust3;
	      dso->shdr[i].sh_offset += adjust3;
	      adjust3 += size - dso->shdr[i].sh_size;
	      dso->shdr[i].sh_size = size;
	    }
	  assert (adjust1 == adjust3);
	  if (rinfo.plt)
	    {
	      dso->shdr[rinfo.plt].sh_addr += adjust1;
	      dso->shdr[rinfo.plt].sh_offset += adjust1;
	    }
	}
      if (rinfo.rel_to_rela_plt)
	dso->shdr[rinfo.plt].sh_size += adjust2;

      if (update_dynamic_rel (dso, &rinfo))
	return 1;
    }

  return 0;
}

static int
prelink_dso (struct prelink_info *info)
{
  int liblist = 0, libstr = 0, nobits_plt = 0;
  int i, ndeps = info->ent->ndepends + 1;
  DSO *dso = info->dso;
  Elf32_Lib *list = NULL;
  Elf_Scn *scn;
  Elf_Data *data;
  GElf_Addr oldsize, oldoffset;
  size_t strsize;

  if (dso->ehdr.e_type != ET_DYN)
    return 0;

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name
	= strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
      if (! strcmp (name, ".gnu.liblist"))
	liblist = i;
      else if (! strcmp (name, ".gnu.libstr"))
	libstr = i;
      else if (! strcmp (name, ".plt") && dso->shdr[i].sh_type == SHT_NOBITS)
	nobits_plt = i;
#if 0
      else if (dso->arch->create_opd && ! strcmp (name, ".opd"))
	opd = i;
#endif
    }

  if (nobits_plt)
    {
      int j, first;
      GElf_Addr adj, last_offset;

      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	if (dso->phdr[i].p_type == PT_LOAD
	    && dso->phdr[i].p_vaddr <= dso->shdr[nobits_plt].sh_addr
	    && dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz
	       >= dso->shdr[nobits_plt].sh_addr
		  + dso->shdr[nobits_plt].sh_size)
	  break;

      if (i == dso->ehdr.e_phnum)
	{
	  error (0, 0, "%s: .plt section not contained within a segment",
		 dso->filename);
	  return 1;
	}

      for (j = i + 1; j < dso->ehdr.e_phnum; ++j)
	if (dso->phdr[j].p_type == PT_LOAD)
	  {
	    error (0, 0, "%s: library's NOBITS .plt section not in loadable last segment",
		   dso->filename);
	    return 1;
	  }

      for (j = nobits_plt - 1; j > 0; --j)
	if (dso->shdr[j].sh_addr < dso->phdr[i].p_vaddr
	    || dso->shdr[j].sh_type != SHT_NOBITS)
	  break;
      first = j + 1;

      for (j = first; j <= nobits_plt; ++j)
	{
	  Elf_Data *data = elf_getdata (dso->scn[j], NULL);

	  assert (data->d_buf == NULL);
	  assert (data->d_size == dso->shdr[j].sh_size);
	  if (data->d_size)
	    {
	      data->d_buf = calloc (data->d_size, 1);
	      if (data->d_buf == NULL)
		{
		  error (0, ENOMEM, "%s: Could not convert NOBITS section into PROGBITS",
			 dso->filename);
		  return 1;
		}
	    }
	  data->d_type = ELF_T_BYTE;
	  dso->shdr[j].sh_type = SHT_PROGBITS;
	  dso->shdr[j].sh_offset = dso->phdr[i].p_offset + dso->shdr[j].sh_addr
				   - dso->phdr[i].p_vaddr;
	}

      adj = dso->shdr[nobits_plt].sh_offset + dso->shdr[nobits_plt].sh_size
	    - dso->phdr[i].p_offset;
      assert (adj <= dso->phdr[i].p_memsz);
      if (adj > dso->phdr[i].p_filesz)
	{
	  adj -= dso->phdr[i].p_filesz;
	  dso->phdr[i].p_filesz += adj;
	  if (adjust_dso_nonalloc (dso, nobits_plt + 1,
				   dso->shdr[first].sh_offset, adj))
	    return 1;
	}

      last_offset = dso->shdr[nobits_plt].sh_offset
		    + dso->shdr[nobits_plt].sh_size;
      for (j = nobits_plt + 1; j < dso->ehdr.e_shnum; ++j)
	if (!(dso->shdr[j].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)))
	  break;
	else
	  {
	    last_offset += dso->shdr[j].sh_addralign - 1;
	    last_offset &= ~(dso->shdr[j].sh_addralign - 1);
	    if (last_offset > dso->phdr[i].p_offset + dso->phdr[i].p_filesz)
	      last_offset = dso->phdr[i].p_offset + dso->phdr[i].p_filesz;
	    dso->shdr[j].sh_offset = last_offset;
	  }
    }

  if (ndeps <= 1)
    return 0;

  assert (liblist != 0);
  assert (libstr != 0);

  list = calloc (ndeps - 1, sizeof (Elf32_Lib));
  if (list == NULL)
    {
      error (0, ENOMEM, "%s: Cannot build .gnu.liblist section",
	     dso->filename);
      goto error_out;
    }

  strsize = 1;
  for (i = 0; i < ndeps - 1; ++i)
    {
      struct prelink_entry *ent = info->ent->depends[i];

      strsize += strlen (info->sonames[i + 1]) + 1;
      list[i].l_time_stamp = ent->timestamp;
      list[i].l_checksum = ent->checksum;
    }

  scn = dso->scn[libstr];
  data = elf_getdata (scn, NULL);
  if (data == NULL)
    data = elf_newdata (scn);
  assert (elf_getdata (scn, data) == NULL);

  data->d_type = ELF_T_BYTE;
  data->d_size = 1;
  data->d_off = 0;
  data->d_align = 1;
  data->d_version = EV_CURRENT;
  data->d_buf = realloc (data->d_buf, strsize);
  if (data->d_buf == NULL)
    {
      error (0, ENOMEM, "%s: Could not build .gnu.libstr section",
	     dso->filename);
      goto error_out;
    }

  oldsize = dso->shdr[libstr].sh_size;
  dso->shdr[libstr].sh_size = 1;
  *(char *)data->d_buf = '\0';
  for (i = 0; i < ndeps - 1; ++i)
    {
      const char *name = info->sonames[i + 1];

      list[i].l_name = strtabfind (dso, liblist, name);
      if (list[i].l_name == 0)
	{
	  size_t len = strlen (name) + 1;

	  memcpy (data->d_buf + data->d_size, name, len);
	  list[i].l_name = data->d_size;
	  data->d_size += len;
	  dso->shdr[libstr].sh_size += len;
	}
    }
  if (oldsize != dso->shdr[libstr].sh_size)
    {
      GElf_Addr adjust = dso->shdr[libstr].sh_size - oldsize;

      oldoffset = dso->shdr[libstr].sh_offset;
      if (adjust_dso_nonalloc (dso, libstr + 1, oldoffset, adjust))
	goto error_out;
    }

  scn = dso->scn[liblist];
  data = elf_getdata (scn, NULL);
  if (data == NULL)
    data = elf_newdata (scn);
  assert (elf_getdata (scn, data) == NULL);

  data->d_type = ELF_T_WORD;
  data->d_size = (ndeps - 1) * sizeof (Elf32_Lib);
  data->d_off = 0;
  data->d_align = sizeof (GElf_Word);
  data->d_version = EV_CURRENT;
  free (data->d_buf);
  data->d_buf = list;
  list = NULL;

  if (data->d_size != dso->shdr[liblist].sh_size)
    {
      GElf_Addr adjust = data->d_size - dso->shdr[liblist].sh_size;
      GElf_Addr newoffset;

      oldoffset = dso->shdr[liblist].sh_offset;
      newoffset = oldoffset;
      if (newoffset & (data->d_align - 1))
	{
	  newoffset = (newoffset + data->d_align - 1) & ~(data->d_align - 1);
	  adjust += newoffset - dso->shdr[liblist].sh_offset;
	}
      if (adjust_dso_nonalloc (dso, liblist + 1, oldoffset, adjust))
	goto error_out;
      dso->shdr[liblist].sh_offset = newoffset;
      dso->shdr[liblist].sh_size = data->d_size;
    }

  recompute_nonalloc_offsets (dso);
  return 0;

error_out:
  free (list);
  return 1;
}

static int
prelink_set_timestamp (struct prelink_info *info)
{
  DSO *dso = info->dso;

  if (! verify)
    info->ent->timestamp = (GElf_Word) time (NULL);
  dso->info_DT_GNU_PRELINKED = info->ent->timestamp;
  if (prelink_set_checksum (dso))
    return 1;
  info->ent->checksum = dso->info_DT_CHECKSUM;
  return 0;
}

static void
free_info (struct prelink_info *info)
{
  int i;

  free (info->symtab);
  free (info->dynbss);
  free (info->sdynbss);
  free (info->conflict_rela);
  if (info->conflicts)
    {
      for (i = 0; i < info->ent->ndepends + 1; ++i)
	{
	  struct prelink_conflict *c = info->conflicts[i];
	  void *f;

	  while (c != NULL)
	    {
	      f = c;
	      c = c->next;
	      free (f);
	    }
	}
      free (info->conflicts);
    }
  if (info->sonames)
    {
      for (i = 0; i < info->ent->ndepends + 1; ++i)
	free ((char *) info->sonames[i]);
      free (info->sonames);
    }
  free (info->tls);
  if (info->symbols)
    {
      for (i = 0; i < info->symbol_count; ++i)
	{
	  struct prelink_symbol *s = info->symbols[i].next;
	  void *f;

	  while (s != NULL)
	    {
	      f = s;
	      s = s->next;
	      free (f);
	    }
	}
      free (info->symbols);
    }
}

int
prelink (DSO *dso, struct prelink_entry *ent)
{
  int i;
  Elf_Scn *scn;
  Elf_Data *data;
  struct prelink_info info;

  ent->pltgot = dso->info[DT_PLTGOT];

  if (! dso->info[DT_SYMTAB])
    return 0;

  if (! dso_is_rdwr (dso) && dso->ehdr.e_type == ET_DYN)
    {
      if (reopen_dso (dso, NULL, NULL))
	return 1;
    }

  i = addr_to_sec (dso, dso->info[DT_SYMTAB]);
  /* DT_SYMTAB should be found and should point to
     start of .dynsym section.  */
  if (i == -1
      || dso->info[DT_SYMTAB] != dso->shdr[i].sh_addr)
    {
      error (0, 0, "%s: Bad symtab", dso->filename);
      return 1;
    }

  memset (&info, 0, sizeof (info));
  info.ent = ent;
  info.symtab_entsize = dso->shdr[i].sh_entsize;
  info.symtab = calloc (dso->shdr[i].sh_size / dso->shdr[i].sh_entsize,
			sizeof (GElf_Sym));
  if (info.symtab == NULL)
    {
      error (0, ENOMEM, "%s: Cannot convert .dynsym section", dso->filename);
      return 1;
    }

  scn = dso->scn[i];
  data = NULL;
  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx, loc;

      loc = data->d_off / info.symtab_entsize;
      maxndx = data->d_size / info.symtab_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	gelfx_getsym (dso->elf, data, ndx, info.symtab + loc + ndx);
    }
  info.symtab_start =
    adjust_new_to_old (dso, dso->shdr[i].sh_addr - dso->base);
  info.symtab_end = info.symtab_start + dso->shdr[i].sh_size;
  info.dso = dso;
  switch (prelink_get_relocations (&info))
    {
    case 0:
      goto error_out;
    case 1:
      info.resolve = resolve_ldso;
      break;
    case 2:
      info.resolve = resolve_dso;
      break;
    }

  if (dso->arch->arch_pre_prelink && dso->arch->arch_pre_prelink (dso))
    goto error_out;

  if (dso->ehdr.e_type == ET_EXEC)
    {
      if (prelink_exec (&info))
	goto error_out;
    }
  else if (prelink_dso (&info))
    goto error_out;

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      if (! (dso->shdr[i].sh_flags & SHF_ALLOC))
	continue;
      if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			    dso->shdr[i].sh_name),
		    ".gnu.conflict"))
	continue;
      switch (dso->shdr[i].sh_type)
	{
	case SHT_REL:
	  if (prelink_rel (dso, i, &info))
	    goto error_out;
	  break;
	case SHT_RELA:
	  if (prelink_rela (dso, i, &info))
	    goto error_out;
	  break;
	}
    }

  if (dso->arch->arch_prelink && dso->arch->arch_prelink (&info))
    goto error_out;

  if (dso->arch->read_opd && dso->arch->read_opd (dso, ent))
    goto error_out;

  /* Must be last.  */
  if (dso->ehdr.e_type == ET_DYN
      && prelink_set_timestamp (&info))
    goto error_out;

  free_info (&info);
  return 0;

error_out:
  free_info (&info);
  return 1;
}
