/* Copyright (C) 2001, 2002, 2003, 2004, 2007, 2009 Red Hat, Inc.
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
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "prelink.h"
#include "reloc.h"

struct prelink_conflict *
prelink_conflict (struct prelink_info *info, GElf_Word r_sym,
		  int reloc_type)
{
  GElf_Word symoff = info->symtab_start + r_sym * info->symtab_entsize;
  struct prelink_conflict *conflict;
  int reloc_class = info->dso->arch->reloc_class (reloc_type);
  size_t idx = 0;

  if (info->curconflicts->hash != &info->curconflicts->first)
    idx = symoff % 251;
  for (conflict = info->curconflicts->hash[idx]; conflict;
       conflict = conflict->next)
    if (conflict->symoff == symoff && conflict->reloc_class == reloc_class)
      {
	conflict->used = 1;
	return conflict;
      }

  return NULL;
}

GElf_Rela *
prelink_conflict_add_rela (struct prelink_info *info)
{
  GElf_Rela *ret;

  if (info->conflict_rela_alloced == info->conflict_rela_size)
    {
      info->conflict_rela_alloced += 10;
      info->conflict_rela = realloc (info->conflict_rela,
				     info->conflict_rela_alloced
				     * sizeof (GElf_Rela));
      if (info->conflict_rela == NULL)
	{
	  error (0, ENOMEM, "Could not build .gnu.conflict section memory image");
	  return NULL;
	}
    }
  ret = info->conflict_rela + info->conflict_rela_size++;
  ret->r_offset = 0;
  ret->r_info = 0;
  ret->r_addend = 0;
  return ret;
}

static int
prelink_conflict_rel (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rel rel;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_conflict_rel (dso, info, &rel, addr))
	    return 1;
	}
    }
  return 0;
}

static int
prelink_conflict_rela (DSO *dso, int n, struct prelink_info *info)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rela rela;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      GElf_Addr addr = dso->shdr[n].sh_addr + data->d_off;

      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx;
	   ++ndx, addr += dso->shdr[n].sh_entsize)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  if (dso->arch->prelink_conflict_rela (dso, info, &rela, addr))
	    return 1;
	}
    }
  return 0;
}

struct copy_relocs
{
  GElf_Rela *rela;
  int alloced;
  int count;
};

static int
prelink_add_copy_rel (DSO *dso, int n, GElf_Rel *rel, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  int symsec = dso->shdr[n].sh_link;
  Elf_Scn *scn = dso->scn[symsec];
  GElf_Sym sym;
  size_t entsize = dso->shdr[symsec].sh_entsize;
  off_t off = GELF_R_SYM (rel->r_info) * entsize;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      if (data->d_off <= off &&
	  data->d_off + data->d_size >= off + entsize)
	{
	  gelfx_getsym (dso->elf, data, (off - data->d_off) / entsize, &sym);
	  if (sym.st_size == 0)
	    {
	      error (0, 0, "%s: Copy reloc against symbol with zero size",
		     dso->filename);
	      return 1;
	    }

	  if (cr->alloced == cr->count)
	    {
	      cr->alloced += 10;
	      cr->rela = realloc (cr->rela, cr->alloced * sizeof (GElf_Rela));
	      if (cr->rela == NULL)
		{
		  error (0, ENOMEM, "%s: Could not build list of COPY relocs",
			 dso->filename);
		  return 1;
		}
	    }
	  cr->rela[cr->count].r_offset = rel->r_offset;
	  cr->rela[cr->count].r_info = rel->r_info;
	  cr->rela[cr->count].r_addend = sym.st_size;
	  ++cr->count;
	  return 0;
	}
    }

  error (0, 0, "%s: Copy reloc against unknown symbol", dso->filename);
  return 1;
}

static int
prelink_find_copy_rel (DSO *dso, int n, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rel rel;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrel (dso->elf, data, ndx, &rel);
	  sec = addr_to_sec (dso, rel.r_offset);
	  if (sec == -1)
	    continue;

	  if (GELF_R_TYPE (rel.r_info) == dso->arch->R_COPY
	      && prelink_add_copy_rel (dso, n, &rel, cr))
	    return 1;
	}
    }
  return 0;
}

static int
prelink_find_copy_rela (DSO *dso, int n, struct copy_relocs *cr)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  union {
    GElf_Rel rel;
    GElf_Rela rela;
  } u;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrela (dso->elf, data, ndx, &u.rela);
	  sec = addr_to_sec (dso, u.rela.r_offset);
	  if (sec == -1)
	    continue;

	  if (GELF_R_TYPE (u.rela.r_info) == dso->arch->R_COPY)
	    {
	      if (u.rela.r_addend != 0)
		{
		  error (0, 0, "%s: COPY reloc with non-zero addend?",
			 dso->filename);
		  return 1;
		}
	      if (prelink_add_copy_rel (dso, n, &u.rel, cr))
		return 1;
	    }
	}
    }
  return 0;
}

static int
rela_cmp (const void *A, const void *B)
{
  GElf_Rela *a = (GElf_Rela *)A;
  GElf_Rela *b = (GElf_Rela *)B;

  if (a->r_offset < b->r_offset)
    return -1;
  if (a->r_offset > b->r_offset)
    return 1;
  return 0;
}

static int
conflict_rela_cmp (const void *A, const void *B)
{
  GElf_Rela *a = (GElf_Rela *)A;
  GElf_Rela *b = (GElf_Rela *)B;

  if (GELF_R_SYM (a->r_info) < GELF_R_SYM (b->r_info))
    return -1;
  if (GELF_R_SYM (a->r_info) > GELF_R_SYM (b->r_info))
    return 1;
  if (a->r_offset < b->r_offset)
    return -1;
  if (a->r_offset > b->r_offset)
    return 1;
  return 0;
}

int
get_relocated_mem (struct prelink_info *info, DSO *dso, GElf_Addr addr,
		   char *buf, GElf_Word size, GElf_Addr dest_addr)
{
  int sec = addr_to_sec (dso, addr), j;
  Elf_Scn *scn;
  Elf_Data *data;
  off_t off;

  if (sec == -1)
    return 1;

  memset (buf, 0, size);
  if (dso->shdr[sec].sh_type != SHT_NOBITS)
    {
      scn = dso->scn[sec];
      data = NULL;
      off = addr - dso->shdr[sec].sh_addr;
      while ((data = elf_rawdata (scn, data)) != NULL)
	{
	  if (data->d_off < off + size
	      && data->d_off + data->d_size > off)
	    {
	      off_t off2 = off - data->d_off;
	      size_t len = size;

	      if (off2 < 0)
		{
		  len += off2;
		  off2 = 0;
		}
	      if (off2 + len > data->d_size)
		len = data->d_size - off2;
	      assert (off2 + len <= data->d_size);
	      assert (len <= size);
	      memcpy (buf + off2 - off, data->d_buf + off2, len);
	    }
	}
    }

  if (info->dso != dso)
    {
      /* This is tricky. We need to apply any conflicts
	 against memory area which we've copied to the COPY
	 reloc offset.  */
      for (j = 0; j < info->conflict_rela_size; ++j)
	{
	  int reloc_type, reloc_size, ret;
	  off_t off;

	  if (info->conflict_rela[j].r_offset >= addr + size)
	    continue;
	  if (info->conflict_rela[j].r_offset + dso->arch->max_reloc_size
	      <= addr)
	    continue;

	  reloc_type = GELF_R_TYPE (info->conflict_rela[j].r_info);
	  reloc_size = dso->arch->reloc_size (reloc_type);
	  if (info->conflict_rela[j].r_offset + reloc_size <= addr)
	    continue;

	  off = info->conflict_rela[j].r_offset - addr;

	  /* Check if whole relocation fits into the area.
	     Punt if not.  */
	  if (off < 0 || size - off < reloc_size)
	    return 2;
	  /* Note that apply_conflict_rela shouldn't rely on R_SYM
	     field of conflict to be 0.  */
	  ret
	    = dso->arch->apply_conflict_rela (info, info->conflict_rela + j,
					      buf + off,
					      dest_addr ? dest_addr + off : 0);
	  if (ret)
	    return ret;
	}
    }
  else
    {
      int i, ndx, maxndx;
      int reloc_type, reloc_size;
      union { GElf_Rel rel; GElf_Rela rela; } u;
      off_t off;

      if (addr + size > info->dynbss_base
	  && addr < info->dynbss_base + info->dynbss_size)
	{
	  if (addr < info->dynbss_base
	      || addr + size > info->dynbss_base + info->dynbss_size)
	    return 4;

	  memcpy (buf, info->dynbss + (addr - info->dynbss_base), size);
	  return 0;
	}

      if (addr + size > info->sdynbss_base
	  && addr < info->sdynbss_base + info->sdynbss_size)
	{
	  if (addr < info->sdynbss_base
	      || addr + size > info->sdynbss_base + info->sdynbss_size)
	    return 4;

	  memcpy (buf, info->sdynbss + (addr - info->sdynbss_base), size);
	  return 0;
	}

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
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
	    case SHT_RELA:
	      break;
	    default:
	      continue;
	    }
	  scn = dso->scn[i];
	  data = NULL;
	  while ((data = elf_getdata (scn, data)) != NULL)
	    {
	      maxndx = data->d_size / dso->shdr[i].sh_entsize;
	      for (ndx = 0; ndx < maxndx; ++ndx)
		{
		  if (dso->shdr[i].sh_type == SHT_REL)
		    gelfx_getrel (dso->elf, data, ndx, &u.rel);
		  else
		    gelfx_getrela (dso->elf, data, ndx, &u.rela);

		  if (u.rel.r_offset >= addr + size)
		    continue;
		  if (u.rel.r_offset + dso->arch->max_reloc_size <= addr)
		    continue;

		  reloc_type = GELF_R_TYPE (u.rel.r_info);
		  reloc_size = dso->arch->reloc_size (reloc_type);
		  if (u.rel.r_offset + reloc_size <= addr)
		    continue;

		  if (reloc_type == dso->arch->R_COPY)
		    return 3;

		  off = u.rel.r_offset - addr;

		  /* Check if whole relocation fits into the area.
		     Punt if not.  */
		  if (off < 0 || size - off < reloc_size)
		    return 2;

		  if (dso->shdr[i].sh_type == SHT_REL)
		    dso->arch->apply_rel (info, &u.rel, buf + off);
		  else
		    dso->arch->apply_rela (info, &u.rela, buf + off);
		}
	    }
	}
    }

  return 0;
}

int
prelink_build_conflicts (struct prelink_info *info)
{
  int i, ndeps = info->ent->ndepends + 1;
  struct prelink_entry *ent;
  int ret = 0;
  DSO *dso;
  struct copy_relocs cr;

  info->dsos = alloca (sizeof (struct DSO *) * ndeps);
  memset (info->dsos, 0, sizeof (struct DSO *) * ndeps);
  memset (&cr, 0, sizeof (cr));
  info->dsos[0] = info->dso;
  for (i = 1; i < ndeps; ++i)
    {
      ent = info->ent->depends[i - 1];
      if ((dso = open_dso (ent->filename)) == NULL)
	goto error_out;
      info->dsos[i] = dso;
      /* Now check that the DSO matches what we recorded about it.  */
      if (ent->timestamp != dso->info_DT_GNU_PRELINKED
	  || ent->checksum != dso->info_DT_CHECKSUM
	  || ent->base != dso->base)
	{
	  error (0, 0, "%s: Library %s has changed since it has been prelinked",
		 info->dso->filename, ent->filename);
	  goto error_out;
	}
    }

  for (i = 0; i < ndeps; ++i)
    {
      int j, sec, first_conflict, maxidx;
      struct prelink_conflict *conflict;

      dso = info->dsos[i];
      ent = i ? info->ent->depends[i - 1] : info->ent;

      /* Verify .gnu.liblist sections of all dependent libraries.  */
      if (i && ent->ndepends > 0)
	{
	  const char *name;
	  int nliblist;
	  Elf32_Lib *liblist;
	  Elf_Scn *scn;
	  Elf_Data *data;

	  for (j = 1; j < dso->ehdr.e_shnum; ++j)
	    if (dso->shdr[j].sh_type == SHT_GNU_LIBLIST
		&& (name = strptr (dso, dso->ehdr.e_shstrndx,
				   dso->shdr[j].sh_name))
		&& ! strcmp (name, ".gnu.liblist")
		&& (dso->shdr[j].sh_size % sizeof (Elf32_Lib)) == 0)
	      break;

	  if (j == dso->ehdr.e_shnum)
	    {
	      error (0, 0, "%s: Library %s has dependencies, but doesn't contain .gnu.liblist section",
		     info->dso->filename, ent->filename);
	      goto error_out;
	    }

	  nliblist = dso->shdr[j].sh_size / sizeof (Elf32_Lib);
	  scn = dso->scn[j];
	  data = elf_getdata (scn, NULL);
	  if (data == NULL || elf_getdata (scn, data)
	      || data->d_buf == NULL || data->d_off
	      || data->d_size != dso->shdr[j].sh_size)
	    {
	      error (0, 0, "%s: Could not read .gnu.liblist section from %s",
		     info->dso->filename, ent->filename);
	      goto error_out;
	    }

	  if (nliblist != ent->ndepends)
	    {
	      error (0, 0, "%s: Library %s has different number of libs in .gnu.liblist than expected",
		     info->dso->filename, ent->filename);
	      goto error_out;
	    }
	  liblist = (Elf32_Lib *) data->d_buf;
	  for (j = 0; j < nliblist; ++j)
	    if (liblist[j].l_time_stamp != ent->depends[j]->timestamp
		|| liblist[j].l_checksum != ent->depends[j]->checksum)
	      {
		error (0, 0, "%s: .gnu.liblist in library %s is inconsistent with recorded dependencies",
		       info->dso->filename, ent->filename);
		goto error_out;
	      }

	  /* Extra check, maybe not needed.  */
	  for (j = 0; j < nliblist; ++j)
	    {
	      int k;
	      for (k = 0; k < info->ent->ndepends; ++k)
		if (liblist[j].l_time_stamp == info->ent->depends[k]->timestamp
		    && liblist[j].l_checksum == info->ent->depends[k]->checksum)
		  break;

	      if (k == info->ent->ndepends)
		abort ();
	    }
	}

      info->curconflicts = &info->conflicts[i];
      info->curtls = info->tls[i].modid ? info->tls + i : NULL;
      first_conflict = info->conflict_rela_size;
      sec = addr_to_sec (dso, dso->info[DT_SYMTAB]);
      /* DT_SYMTAB should be found and should point to
	 start of .dynsym section.  */
      if (sec == -1 || dso->info[DT_SYMTAB] != dso->shdr[sec].sh_addr)
	{
	  error (0, 0, "Bad symtab");
	  goto error_out;
	}
      info->symtab_start = dso->shdr[sec].sh_addr - dso->base;
      info->symtab_end = info->symtab_start + dso->shdr[sec].sh_size;
      for (j = 0; j < dso->ehdr.e_shnum; ++j)
	{
	  if (! (dso->shdr[j].sh_flags & SHF_ALLOC))
	    continue;
	  switch (dso->shdr[j].sh_type)
	    {
	    case SHT_REL:
	      if (i == 0
		  && strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				     dso->shdr[j].sh_name),
			     ".gnu.conflict") == 0)
		break;
	      if (prelink_conflict_rel (dso, j, info))
		goto error_out;
	      break;
	    case SHT_RELA:
	      if (i == 0
		  && strcmp (strptr (dso, dso->ehdr.e_shstrndx,
				     dso->shdr[j].sh_name),
			     ".gnu.conflict") == 0)
		break;
	      if (prelink_conflict_rela (dso, j, info))
		goto error_out;
	      break;
	    }
	}

      if (dso->arch->arch_prelink_conflict
	  && dso->arch->arch_prelink_conflict (dso, info))
	goto error_out;

      maxidx = 1;
      if (info->curconflicts->hash != &info->curconflicts->first)
	maxidx = 251;
      for (j = 0; j < maxidx; j++)
	for (conflict = info->curconflicts->hash[j]; conflict;
	     conflict = conflict->next)
	  if (! conflict->used && (i || conflict->ifunc))
	    {
	      error (0, 0, "%s: Conflict %08llx not found in any relocation",
		     dso->filename, (unsigned long long) conflict->symoff);
	      ret = 1;
	    }

      /* Record library's position in search scope into R_SYM field.  */
      for (j = first_conflict; j < info->conflict_rela_size; ++j)
	info->conflict_rela[j].r_info
	  = GELF_R_INFO (i, GELF_R_TYPE (info->conflict_rela[j].r_info));

      if (dynamic_info_is_set (dso, DT_TEXTREL)
	  && info->conflict_rela_size > first_conflict)
	{
	  /* We allow prelinking against non-PIC libraries, as long as
	     no conflict is against read-only segment.  */
	  int k;

	  for (j = first_conflict; j < info->conflict_rela_size; ++j)
	    for (k = 0; k < dso->ehdr.e_phnum; ++k)
	      if (dso->phdr[k].p_type == PT_LOAD
		  && (dso->phdr[k].p_flags & PF_W) == 0
		  && dso->phdr[k].p_vaddr
		     <= info->conflict_rela[j].r_offset
		  && dso->phdr[k].p_vaddr + dso->phdr[k].p_memsz
		     > info->conflict_rela[j].r_offset)
		{
		  error (0, 0, "%s: Cannot prelink against non-PIC shared library %s",
			 info->dso->filename, dso->filename);
		  goto error_out;
		}
	}
    }

  dso = info->dso;
  for (i = 0; i < dso->ehdr.e_shnum; ++i)
    {
      if (! (dso->shdr[i].sh_flags & SHF_ALLOC))
	continue;
      switch (dso->shdr[i].sh_type)
	{
	case SHT_REL:
	  if (prelink_find_copy_rel (dso, i, &cr))
	    goto error_out;
	  break;
	case SHT_RELA:
	  if (prelink_find_copy_rela (dso, i, &cr))
	    goto error_out;
	  break;
	}
    }

  if (cr.count)
    {
      int bss1, bss2, firstbss2 = 0;
      const char *name;

      qsort (cr.rela, cr.count, sizeof (GElf_Rela), rela_cmp);
      bss1 = addr_to_sec (dso, cr.rela[0].r_offset);
      bss2 = addr_to_sec (dso, cr.rela[cr.count - 1].r_offset);
      if (bss1 != bss2)
	{
	  for (i = 1; i < cr.count; ++i)
	    if (cr.rela[i].r_offset
		> dso->shdr[bss1].sh_addr + dso->shdr[bss1].sh_size)
	      break;
	  if (cr.rela[i].r_offset < dso->shdr[bss2].sh_addr)
	    {
	      error (0, 0, "%s: Copy relocs against 3 or more sections",
		     dso->filename);
	      goto error_out;
	    }
	  firstbss2 = i;
	  info->sdynbss_size = cr.rela[i - 1].r_offset - cr.rela[0].r_offset;
	  info->sdynbss_size += cr.rela[i - 1].r_addend;
	  info->sdynbss = calloc (info->sdynbss_size, 1);
	  info->sdynbss_base = cr.rela[0].r_offset;
	  if (info->sdynbss == NULL)
	    {
	      error (0, ENOMEM, "%s: Cannot build .sdynbss", dso->filename);
	      goto error_out;
	    }

	  for (i = 0; i < dso->ehdr.e_phnum; ++i)
	    if (dso->phdr[i].p_type == PT_LOAD
		&& dso->shdr[bss1].sh_addr >= dso->phdr[i].p_vaddr
		&& dso->shdr[bss1].sh_addr
		   < dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	      break;
	  if (i == dso->ehdr.e_phnum
	      || dso->shdr[bss2].sh_addr + dso->shdr[bss2].sh_size
		 > dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	    {
	      error (0, 0, "%s: Copy relocs against more than one segment",
		     dso->filename);
	      goto error_out;
	    }
	}

      info->dynbss_size = cr.rela[cr.count - 1].r_offset
			  - cr.rela[firstbss2].r_offset;
      info->dynbss_size += cr.rela[cr.count - 1].r_addend;
      info->dynbss = calloc (info->dynbss_size, 1);
      info->dynbss_base = cr.rela[firstbss2].r_offset;
      if (info->dynbss == NULL)
	{
	  error (0, ENOMEM, "%s: Cannot build .dynbss", dso->filename);
	  goto error_out;
	}

      /* emacs apparently has .rel.bss relocations against .data section,
	 crap.  */
      if (dso->shdr[bss1].sh_type != SHT_NOBITS
	  && strcmp (name = strptr (dso, dso->ehdr.e_shstrndx,
				    dso->shdr[bss1].sh_name),
		     ".dynbss") != 0
	  && strcmp (name, ".sdynbss") != 0)
	{
	  error (0, 0, "%s: COPY relocations don't point into .bss or .sbss section",
		 dso->filename);
	  goto error_out;
	}
      if (bss1 != bss2
	  && dso->shdr[bss2].sh_type != SHT_NOBITS
	  && strcmp (name = strptr (dso, dso->ehdr.e_shstrndx,
				    dso->shdr[bss2].sh_name),
		     ".dynbss") != 0
	  && strcmp (name, ".sdynbss") != 0)
	{
	  error (0, 0, "%s: COPY relocations don't point into .bss or .sbss section",
		 dso->filename);
	  goto error_out;
	}

      for (i = 0; i < cr.count; ++i)
	{
	  struct prelink_symbol *s;
	  DSO *ndso = NULL;
	  int j, reloc_class;

	  reloc_class
	    = dso->arch->reloc_class (GELF_R_TYPE (cr.rela[i].r_info));

	  assert (reloc_class != RTYPE_CLASS_TLS);

	  for (s = & info->symbols[GELF_R_SYM (cr.rela[i].r_info)]; s;
	       s = s->next)
	    if (s->reloc_class == reloc_class)
	      break;

	  if (s == NULL || s->u.ent == NULL)
	    {
	      error (0, 0, "%s: Could not find symbol copy reloc is against",
		     dso->filename);
	      goto error_out;
	    }

	  for (j = 1; j < ndeps; ++j)
	    if (info->ent->depends[j - 1] == s->u.ent)
	      {
		ndso = info->dsos[j];
		break;
	      }

	  assert (j < ndeps);
	  if (i < firstbss2)
	    j = get_relocated_mem (info, ndso, s->u.ent->base + s->value,
				   info->sdynbss + cr.rela[i].r_offset
				   - info->sdynbss_base, cr.rela[i].r_addend,
				   cr.rela[i].r_offset);
	  else
	    j = get_relocated_mem (info, ndso, s->u.ent->base + s->value,
				   info->dynbss + cr.rela[i].r_offset
				   - info->dynbss_base, cr.rela[i].r_addend,
				   cr.rela[i].r_offset);

	  switch (j)
	    {
	    case 1:
	      error (0, 0, "%s: Could not find variable copy reloc is against",
		     dso->filename);
	      goto error_out;
	    case 2:
	      error (0, 0, "%s: Conflict partly overlaps with %08llx-%08llx area",
		     dso->filename,
		     (long long) cr.rela[i].r_offset,
		     (long long) (cr.rela[i].r_offset + cr.rela[i].r_addend));
	      goto error_out;
	    }
	}
    }

  if (info->conflict_rela_size)
    {
      qsort (info->conflict_rela, info->conflict_rela_size, sizeof (GElf_Rela),
	     conflict_rela_cmp);

      /* Now make sure all conflict RELA's are against absolute 0 symbol.  */
      for (i = 0; i < info->conflict_rela_size; ++i)
	info->conflict_rela[i].r_info
	  = GELF_R_INFO (0, GELF_R_TYPE (info->conflict_rela[i].r_info));

      if (enable_cxx_optimizations && remove_redundant_cxx_conflicts (info))
	goto error_out;
    }

  for (i = 1; i < ndeps; ++i)
    if (info->dsos[i])
      close_dso (info->dsos[i]);

  info->dsos = NULL;
  free (cr.rela);
  return ret;

error_out:
  free (cr.rela);
  free (info->dynbss);
  free (info->sdynbss);
  info->dynbss = NULL;
  info->sdynbss = NULL;
  for (i = 1; i < ndeps; ++i)
    if (info->dsos[i])
      close_dso (info->dsos[i]);
  return 1;
}
