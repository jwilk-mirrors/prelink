/* Copyright (C) 2001, 2002, 2003, 2005, 2010 Red Hat, Inc.
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

static int
undo_prelink_rel (DSO *dso, int n)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rel rel;
  int sec;

  if (dso->arch->undo_prelink_rel == NULL)
    return 0;
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

	  switch (dso->arch->undo_prelink_rel (dso, &rel, addr))
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
undo_prelink_rela (DSO *dso, int n)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rela rela;
  int sec;

  if (dso->arch->undo_prelink_rela == NULL)
    return 0;
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

	  switch (dso->arch->undo_prelink_rela (dso, &rela, addr))
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

static int
remove_dynamic_prelink_tags (DSO *dso)
{
  Elf_Data *data;
  Elf_Scn *scn;
  GElf_Dyn dyn;
  int ndx;

  assert (dso->shdr[dso->dynamic].sh_type == SHT_DYNAMIC);
  scn = dso->scn[dso->dynamic];
  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);
  ndx = data->d_size / dso->shdr[dso->dynamic].sh_entsize;
  while (--ndx >= 0)
    {
      gelfx_getdyn (dso->elf, data, ndx, &dyn);
      switch (dyn.d_tag)
	{
	case DT_NULL:
	  continue;
	case DT_CHECKSUM:
	case DT_GNU_PRELINKED:
	case DT_GNU_LIBLIST:
	case DT_GNU_LIBLISTSZ:
	case DT_GNU_CONFLICT:
	case DT_GNU_CONFLICTSZ:
	  dyn.d_tag = DT_NULL;
	  dyn.d_un.d_val = 0;
	  gelfx_update_dyn (dso->elf, data, ndx, &dyn);
	  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
	  break;
	default:
	  ndx = 0;
	  break;
	}
    }
  return 0;
}

int
undo_sections (DSO *dso, int undo, struct section_move *move,
	       struct reloc_info *rinfo, GElf_Ehdr *ehdr,
	       GElf_Phdr *phdr, GElf_Shdr *shdr)
{
  Elf_Data src, dst, *d;
  Elf_Scn *scn;
  int i, j;

  scn = dso->scn[undo];
  d = elf_getdata (scn, NULL);
  assert (d != NULL && elf_getdata (scn, d) == NULL);

  src = *d;
  src.d_type = ELF_T_EHDR;
  src.d_align = dso->shdr[undo].sh_addralign;
  src.d_size = gelf_fsize (dso->elf, ELF_T_EHDR, 1, EV_CURRENT);
  dst = src;
  if (src.d_size > d->d_size)
    {
      error (0, 0, "%s: .gnu.prelink_undo section too small",
	     dso->filename);
      return 1;
    }
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      dst.d_buf = alloca (dst.d_size);
      break;
    case ELFCLASS64:
      dst.d_buf = ehdr;
      break;
    default:
      return 1;
    }
  if (gelf_xlatetom (dso->elf, &dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
    {
      error (0, 0, "%s: Could not read .gnu.prelink_undo section",
	     dso->filename);
      return 1;
    }
  if (gelf_getclass (dso->elf) == ELFCLASS32)
    {
      Elf32_Ehdr *ehdr32 = (Elf32_Ehdr *) dst.d_buf;

      memcpy (ehdr->e_ident, ehdr32->e_ident, sizeof (ehdr->e_ident));
#define COPY(name) ehdr->name = ehdr32->name
      COPY (e_type);
      COPY (e_machine);
      COPY (e_version);
      COPY (e_entry);
      COPY (e_phoff);
      COPY (e_shoff);
      COPY (e_flags);
      COPY (e_ehsize);
      COPY (e_phentsize);
      COPY (e_phnum);
      COPY (e_shentsize);
      COPY (e_shnum);
      COPY (e_shstrndx);
#undef COPY
    }

  if (memcmp (ehdr->e_ident, dso->ehdr.e_ident, sizeof (ehdr->e_ident))
      || ehdr->e_type != dso->ehdr.e_type
      || ehdr->e_machine != dso->ehdr.e_machine
      || ehdr->e_version != dso->ehdr.e_version
      || ehdr->e_flags != dso->ehdr.e_flags
      || ehdr->e_ehsize != dso->ehdr.e_ehsize
      || ehdr->e_phentsize != dso->ehdr.e_phentsize
      || ehdr->e_shentsize != dso->ehdr.e_shentsize)
    {
      error (0, 0, "%s: ELF headers changed since prelinking",
	     dso->filename);
      return 1;
    }

  if (ehdr->e_phnum > dso->ehdr.e_phnum)
    {
      error (0, 0, "%s: Number of program headers is less than before prelinking",
	     dso->filename);
      return 1;
    }

  if (d->d_size != (src.d_size
		    + gelf_fsize (dso->elf, ELF_T_PHDR, ehdr->e_phnum,
				  EV_CURRENT)
		    + gelf_fsize (dso->elf, ELF_T_SHDR, ehdr->e_shnum - 1,
				  EV_CURRENT)))
    {
      error (0, 0, "%s: Incorrect size of .gnu.prelink_undo section",
	     dso->filename);
      return 1;
    }

  src.d_type = ELF_T_PHDR;
  src.d_buf += src.d_size;
  src.d_size = gelf_fsize (dso->elf, ELF_T_PHDR, ehdr->e_phnum, EV_CURRENT);
  dst = src;
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      dst.d_buf = alloca (dst.d_size);
      break;
    case ELFCLASS64:
      dst.d_buf = phdr;
      break;
    }
  if (gelf_xlatetom (dso->elf, &dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
    {
      error (0, 0, "%s: Could not read .gnu.prelink_undo section",
	     dso->filename);
      return 1;
    }

  if (gelf_getclass (dso->elf) == ELFCLASS32)
    {
      Elf32_Phdr *phdr32 = (Elf32_Phdr *) dst.d_buf;

      for (i = 0; i < ehdr->e_phnum; ++i)
	{
#define COPY(name) phdr[i].name = phdr32[i].name
	  COPY(p_type);
	  COPY(p_flags);
	  COPY(p_offset);
	  COPY(p_vaddr);
	  COPY(p_paddr);
	  COPY(p_filesz);
	  COPY(p_memsz);
	  COPY(p_align);
#undef COPY
	}
    }

  memset (shdr, 0, sizeof (GElf_Shdr));
  src.d_type = ELF_T_SHDR;
  src.d_buf += src.d_size;
  src.d_size = gelf_fsize (dso->elf, ELF_T_SHDR, ehdr->e_shnum - 1, EV_CURRENT);
  dst = src;
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      dst.d_buf = alloca (dst.d_size);
      break;
    case ELFCLASS64:
      dst.d_buf = shdr + 1;
      break;
    default:
      return 1;
    }
  if (gelf_xlatetom (dso->elf, &dst, &src, dso->ehdr.e_ident[EI_DATA]) == NULL)
    {
      error (0, 0, "%s: Could not read .gnu.prelink_undo section",
	     dso->filename);
      return 1;
    }

  if (gelf_getclass (dso->elf) == ELFCLASS32)
    {
      Elf32_Shdr *shdr32 = (Elf32_Shdr *) dst.d_buf;

      for (i = 1; i < ehdr->e_shnum; ++i)
	{
#define COPY(name) shdr[i].name = shdr32[i - 1].name
	  COPY (sh_name);
	  COPY (sh_type);
	  COPY (sh_flags);
	  COPY (sh_addr);
	  COPY (sh_offset);
	  COPY (sh_size);
	  COPY (sh_link);
	  COPY (sh_info);
	  COPY (sh_addralign);
	  COPY (sh_entsize);
#undef COPY
	}
    }

  move->new_shnum = ehdr->e_shnum;
  for (i = 1; i < move->old_shnum; ++i)
    move->old_to_new[i] = -1;
  for (i = 1; i < move->new_shnum; ++i)
    move->new_to_old[i] = -1;

  for (i = 1; i < move->old_shnum; ++i)
    {
      for (j = 1; j < move->new_shnum; ++j)
	if (dso->shdr[i].sh_name == shdr[j].sh_name
	    && dso->shdr[i].sh_type == shdr[j].sh_type
	    && dso->shdr[i].sh_flags == shdr[j].sh_flags
	    && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
	    && dso->shdr[i].sh_entsize == shdr[j].sh_entsize
	    && dso->shdr[i].sh_size == shdr[j].sh_size
	    && move->new_to_old[j] == -1)
	  break;

      if (j == move->new_shnum)
	continue;

      move->old_to_new[i] = j;
      move->new_to_old[j] = i;
    }

  for (i = 1; i < move->old_shnum; ++i)
    if (move->old_to_new[i] == -1)
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				   dso->shdr[i].sh_name);

	if (! strcmp (name, ".gnu.prelink_undo")
	    || ! strcmp (name, ".gnu.conflict")
	    || ! strcmp (name, ".gnu.liblist")
	    || ! strcmp (name, ".gnu.libstr")
	    || ((! strcmp (name, ".dynbss") || ! strcmp (name, ".sdynbss"))
		&& dso->ehdr.e_type == ET_EXEC))
	  continue;

	if ((! strcmp (name, ".dynstr") && dso->ehdr.e_type == ET_EXEC)
	    || i == dso->ehdr.e_shstrndx)
	  {
	    for (j = 1; j < move->new_shnum; ++j)
	      if (dso->shdr[i].sh_name == shdr[j].sh_name
		  && dso->shdr[i].sh_type == shdr[j].sh_type
		  && dso->shdr[i].sh_flags == shdr[j].sh_flags
		  && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
		  && dso->shdr[i].sh_entsize == shdr[j].sh_entsize
		  && dso->shdr[i].sh_size > shdr[j].sh_size
		  && move->new_to_old[j] == -1)
		break;

	    if (j < move->new_shnum)
	      {
		move->old_to_new[i] = j;
		move->new_to_old[j] = i;
		continue;
	      }
	  }

	if (((i >= rinfo->first && i <= rinfo->last) || i == rinfo->plt)
	    && dso->shdr[i].sh_type == SHT_RELA)
	  {
	    for (j = 1; j < move->new_shnum; ++j)
	      if (dso->shdr[i].sh_name == shdr[j].sh_name
		  && shdr[j].sh_type == SHT_REL
		  && dso->shdr[i].sh_flags == shdr[j].sh_flags
		  && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
		  && 2 * dso->shdr[i].sh_entsize == 3 * shdr[j].sh_entsize
		  && 2 * dso->shdr[i].sh_size == 3 * shdr[j].sh_size
		  && move->new_to_old[j] == -1)
		break;

	    if (j < move->new_shnum)
	      {
		move->old_to_new[i] = j;
		move->new_to_old[j] = i;
		continue;
	      }
	  }

	if (! strcmp (name, ".bss")
	    || ! strcmp (name, ".sbss")
	    || ((! strcmp (name, ".plt") || ! strcmp (name, ".iplt"))
		&& dso->shdr[i].sh_type == SHT_PROGBITS))
	  {
	    int is_plt = ! strcmp (name, ".plt");

	    for (j = 1; j < move->new_shnum; ++j)
	      if (dso->shdr[i].sh_name == shdr[j].sh_name
		  && dso->shdr[i].sh_flags == shdr[j].sh_flags
		  && dso->shdr[i].sh_addralign == shdr[j].sh_addralign
		  && (is_plt || dso->shdr[i].sh_entsize == shdr[j].sh_entsize)
		  && move->new_to_old[j] == -1)
		{
		  if (is_plt)
		    {
		      if (dso->shdr[i].sh_size != shdr[j].sh_size)
			continue;
		      if (shdr[j].sh_type == SHT_NOBITS
			  && dso->shdr[i].sh_entsize == shdr[j].sh_entsize)
			break;
		      /* On Alpha prelink fixes bogus sh_entsize of .plt
			 sections.  */
		      if (shdr[j].sh_type == SHT_PROGBITS)
			break;
		    }
		  else
		    {
		      const char *pname;

		      if (dso->shdr[i].sh_type != shdr[j].sh_type
			  && (dso->shdr[i].sh_type != SHT_PROGBITS
			      || shdr[j].sh_type != SHT_NOBITS))
			continue;

		      if (dso->shdr[i].sh_size == shdr[j].sh_size)
			break;

		      pname = strptr (dso, dso->ehdr.e_shstrndx,
				      dso->shdr[i - 1].sh_name);
		      if (strcmp (pname, ".dynbss")
			  && strcmp (pname, ".sdynbss"))
			continue;

		      if (dso->shdr[i].sh_size + dso->shdr[i - 1].sh_size
			  == shdr[j].sh_size)
			break;
		    }
		}

	    if (j < move->new_shnum)
	      {
		move->old_to_new[i] = j;
		move->new_to_old[j] = i;
		continue;
	      }
	  }

	error (0, 0, "%s: Section %s created after prelinking",
	       dso->filename, name);
	return 1;
      }

  for (i = 1; i < move->new_shnum; ++i)
    if (move->new_to_old[i] == -1)
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx, shdr[i].sh_name);

	error (0, 0, "%s: Section %s removed after prelinking", dso->filename,
	       name);
	return 1;
      }

  return 0;
}

int
prelink_undo (DSO *dso)
{
  GElf_Ehdr ehdr;
  GElf_Shdr shdr[dso->ehdr.e_shnum + 20], old_shdr[dso->ehdr.e_shnum];
  GElf_Phdr phdr[dso->ehdr.e_phnum];
  Elf_Scn *scn;
  Elf_Data *d;
  int undo, i;
  struct section_move *move;
  struct reloc_info rinfo;

  for (undo = 1; undo < dso->ehdr.e_shnum; ++undo)
    if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[undo].sh_name),
		  ".gnu.prelink_undo"))
      break;

  if (undo == dso->ehdr.e_shnum)
    {
      if (undo_output)
	return 0;
      error (0, 0, "%s does not have .gnu.prelink_undo section", dso->filename);
      return 1;
    }

  memcpy (old_shdr, dso->shdr, sizeof (GElf_Shdr) * dso->ehdr.e_shnum);
  move = init_section_move (dso);
  if (move == NULL)
    return 1;

  if (find_reloc_sections (dso, &rinfo))
    goto error_out;

  if (undo_sections (dso, undo, move, &rinfo, &ehdr, phdr, shdr))
    goto error_out;

  if (reopen_dso (dso, move, (undo_output && strcmp (undo_output, "-") == 0)
			     ? "/tmp/undo" : undo_output))
    goto error_out;

  if (find_reloc_sections (dso, &rinfo))
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
	  if (undo_prelink_rel (dso, i))
	    goto error_out;
	  break;
	case SHT_RELA:
	  if (undo_prelink_rela (dso, i))
	    goto error_out;
	  break;
	}
    }

  if (dso->arch->arch_undo_prelink && dso->arch->arch_undo_prelink (dso))
    goto error_out;

  if (dso->ehdr.e_type == ET_DYN)
    {
      GElf_Addr adjust = 0, diff;

      for (i = dso->ehdr.e_shnum - 1; i > 0; --i)
	if (shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))
	  {
	    adjust = shdr[i].sh_addr - dso->shdr[i].sh_addr;
	    break;
	  }
      while (i > 0)
	{
	  int nsec = 1, j;
	  /* Change here PROGBITS .plt into NOBITS if needed.  */

	  /* Convert RELA to REL if needed.  */
	  if (dso->shdr[i].sh_type == SHT_RELA && shdr[i].sh_type == SHT_REL)
	    {
	      assert (dso->arch->rela_to_rel != NULL);
	      if (i == rinfo.plt)
		{
		  if (convert_rela_to_rel (dso, i))
		    goto error_out;
		  dso->shdr[i].sh_size = shdr[i].sh_size;
		}
	      else if (i == rinfo.last)
		{
		  GElf_Addr start = dso->shdr[rinfo.first].sh_addr;

		  for (j = rinfo.first; j <= rinfo.last; ++j)
		    {
		      if (convert_rela_to_rel (dso, j))
			goto error_out;
		      dso->shdr[j].sh_addr = start;
		      dso->shdr[j].sh_size = shdr[j].sh_size;
		      start += dso->shdr[j].sh_size;
		    }
		  nsec = rinfo.last - rinfo.first + 1;
		  i = rinfo.first;
		}
	      else
		{
		  error (0, 0, "%s: Cannot convert RELA to REL", dso->filename);
		  goto error_out;
		}
	    }
	  diff = shdr[i].sh_addr - dso->shdr[i].sh_addr;
	  if (diff != adjust)
	    {
	      assert (diff >= adjust);
	      if (adjust_dso (dso, dso->shdr[i + nsec].sh_addr, adjust - diff))
		goto error_out;
	      adjust = diff;
	    }
	  --i;
	}
      if (adjust && adjust_dso (dso, 0, adjust))
	goto error_out;
      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	if (shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))
	  assert (shdr[i].sh_addr == dso->shdr[i].sh_addr);
    }
  else
    {
      /* Executable.  */
      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	{
	  const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				     dso->shdr[i].sh_name);

	  if (dso->shdr[i].sh_type == SHT_PROGBITS
	      && shdr[i].sh_type == SHT_NOBITS)
	    {
	      assert (strcmp (name, ".bss") == 0
		      || strcmp (name, ".sbss") == 0
		      || strcmp (name, ".plt") == 0
		      || strcmp (name, ".iplt") == 0);
	      scn = dso->scn[i];
	      d = elf_getdata (scn, NULL);
	      assert (d != NULL && elf_getdata (scn, d) == NULL);
	      assert (d->d_size == 0 || d->d_buf != NULL);
	      assert (d->d_size == dso->shdr[i].sh_size);
	      free (d->d_buf);
	      d->d_buf = NULL;
	      dso->shdr[i].sh_type = SHT_NOBITS;
	    }
	  else if (dso->shdr[i].sh_type == SHT_RELA
		   && shdr[i].sh_type == SHT_REL)
	    {
	      if (convert_rela_to_rel (dso, i))
		goto error_out;
	      dso->shdr[i].sh_size = shdr[i].sh_size;
	    }
	  else
	    assert (dso->shdr[i].sh_type == shdr[i].sh_type);
	  if (dso->shdr[i].sh_size != shdr[i].sh_size)
	    {
	      /* This is handled in code below for both ET_DYN and ET_EXEC.  */
	      if (i == dso->ehdr.e_shstrndx)
		continue;
	      assert (shdr[i].sh_type == SHT_NOBITS
		      || shdr[i].sh_size < dso->shdr[i].sh_size);
	      assert (strcmp (name, ".dynstr") == 0
		      || strcmp (name, ".bss") == 0
		      || strcmp (name, ".sbss") == 0);
	      scn = dso->scn[i];
	      d = elf_getdata (scn, NULL);
	      assert (d != NULL && elf_getdata (scn, d) == NULL);
	      d->d_size = shdr[i].sh_size;
	    }
	}

      if (update_dynamic_tags (dso, shdr, old_shdr, move))
	goto error_out;

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	if (shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))
	  dso->shdr[i].sh_addr = shdr[i].sh_addr;
    }

  /* Clear .dynamic entries added by prelink, update others.  */
  if (remove_dynamic_prelink_tags (dso)
      || update_dynamic_rel (dso, &rinfo))
    goto error_out;

  /* Shrink .shstrtab.  */
  i = dso->ehdr.e_shstrndx;
  if (shdr[i].sh_size < dso->shdr[i].sh_size)
    {
      scn = dso->scn[i];
      d = elf_getdata (scn, NULL);
      assert (d != NULL && elf_getdata (scn, d) == NULL);
      assert (d->d_size == dso->shdr[i].sh_size);
      d->d_size = shdr[i].sh_size;
    }

  /* Now restore the rest.  */
  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    dso->shdr[i] = shdr[i];
  if (dso->ehdr.e_phnum != ehdr.e_phnum)
    {
      assert (ehdr.e_phnum < dso->ehdr.e_phnum);
      if (gelf_newphdr (dso->elf, ehdr.e_phnum) == 0)
	{
	  error (0, 0, "Could not create new ELF headers");
	  goto error_out;
	}
    }
  for (i = 0; i < ehdr.e_phnum; ++i)
    dso->phdr[i] = phdr[i];
  dso->permissive = 1;
  assert (dso->ehdr.e_entry == ehdr.e_entry);
  assert (dso->ehdr.e_shnum == ehdr.e_shnum);
  assert (dso->ehdr.e_shstrndx == ehdr.e_shstrndx);
  dso->ehdr.e_phoff = ehdr.e_phoff;
  dso->ehdr.e_shoff = ehdr.e_shoff;
  dso->ehdr.e_phnum = ehdr.e_phnum;
  free (move);
  return 0;

error_out:
  free (move);
  return 1;
}
