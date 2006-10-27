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
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "prelink.h"

#if defined HAVE_LIBSELINUX && defined HAVE_SELINUX_SELINUX_H
#include <selinux/selinux.h>
#define USE_SELINUX
#endif

#define RELOCATE_SCN(shf) \
  ((shf) & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))

#ifndef ELF_F_PERMISSIVE
# define ELF_F_PERMISSIVE 0
#endif

void
read_dynamic (DSO *dso)
{
  int i;

  memset (dso->info, 0, sizeof(dso->info));
  dso->info_set_mask = 0;
  for (i = 0; i < dso->ehdr.e_shnum; i++)
    if (dso->shdr[i].sh_type == SHT_DYNAMIC)
      {
	Elf_Data *data = NULL;
	Elf_Scn *scn = dso->scn[i];
	GElf_Dyn dyn;

	dso->dynamic = i;
	while ((data = elf_getdata (scn, data)) != NULL)
	  {
	    int ndx, maxndx;

	    maxndx = data->d_size / dso->shdr[i].sh_entsize;
	    for (ndx = 0; ndx < maxndx; ++ndx)
	      {
		gelfx_getdyn (dso->elf, data, ndx, &dyn);
		if (dyn.d_tag == DT_NULL)
		  break;
		else if ((GElf_Xword) dyn.d_tag < DT_NUM)
		  {
		    dso->info[dyn.d_tag] = dyn.d_un.d_val;
		    if (dyn.d_tag < 50)
		      dso->info_set_mask |= (1ULL << dyn.d_tag);
		  }
		else if (dyn.d_tag == DT_CHECKSUM)
		  {
		    dso->info_DT_CHECKSUM = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_CHECKSUM_BIT);
		  }
		else if (dyn.d_tag == DT_GNU_PRELINKED)
		  {
		    dso->info_DT_GNU_PRELINKED = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_GNU_PRELINKED_BIT);
		  }
		else if (dyn.d_tag == DT_VERDEF)
		  {
		    dso->info_DT_VERDEF = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERDEF_BIT);
		  }
		else if (dyn.d_tag == DT_VERNEED)
		  {
		    dso->info_DT_VERNEED = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERNEED_BIT);
		  }
		else if (dyn.d_tag == DT_VERSYM)
		  {
		    dso->info_DT_VERSYM = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_VERSYM_BIT);
		  }
		else if (dyn.d_tag == DT_FILTER)
		  dso->info_set_mask |= (1ULL << DT_FILTER_BIT);
		else if (dyn.d_tag == DT_AUXILIARY)
		  dso->info_set_mask |= (1ULL << DT_AUXILIARY_BIT);
		else if (dyn.d_tag == DT_LOPROC)
		  dso->info_set_mask |= (1ULL << DT_LOPROC_BIT);
		else if (dyn.d_tag == DT_GNU_HASH)
		  {
		    dso->info_DT_GNU_HASH = dyn.d_un.d_val;
		    dso->info_set_mask |= (1ULL << DT_GNU_HASH_BIT);
		  }
	      }
	    if (ndx < maxndx)
	      break;
	  }
      }
}

int
set_dynamic (DSO *dso, GElf_Word tag, GElf_Addr value, int fatal)
{
  Elf_Data *data;
  Elf_Scn *scn;
  GElf_Dyn dyn;
  int ndx, maxndx;
  uint64_t mask = dso->info_set_mask;

  assert (dso->shdr[dso->dynamic].sh_type == SHT_DYNAMIC);

  scn = dso->scn[dso->dynamic];

  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);

  switch (tag)
    {
    case DT_CHECKSUM:
      mask |= (1ULL << DT_CHECKSUM_BIT); break;
    case DT_GNU_PRELINKED:
      mask |= (1ULL << DT_GNU_PRELINKED_BIT); break;
    case DT_VERDEF:
      mask |= (1ULL << DT_VERDEF_BIT); break;
    case DT_VERNEED:
      mask |= (1ULL << DT_VERNEED_BIT); break;
    case DT_VERSYM:
      mask |= (1ULL << DT_VERSYM_BIT); break;
    default:
      if (tag < DT_NUM && tag < 50)
	mask |= (1ULL << tag);
      break;
    }

  maxndx = data->d_size / dso->shdr[dso->dynamic].sh_entsize;
  for (ndx = 0; ndx < maxndx; ndx++)
    {
      gelfx_getdyn (dso->elf, data, ndx, &dyn);
      if (dyn.d_tag == DT_NULL)
	break;
      else if (dyn.d_tag == tag)
	{
	  if (dyn.d_un.d_ptr != value)
	    {
	      dyn.d_un.d_ptr = value;
	      gelfx_update_dyn (dso->elf, data, ndx, &dyn);
	      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
	    }

	  return 0;
	}
    }
  assert (ndx < maxndx);

  if (ndx + 1 < maxndx)
    {
      /* DT_NULL is not the last dynamic entry.  */
      gelfx_update_dyn (dso->elf, data, ndx + 1, &dyn);
      dyn.d_tag = tag;
      dyn.d_un.d_ptr = value;
      gelfx_update_dyn (dso->elf, data, ndx, &dyn);
      dso->info_set_mask = mask;
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      return 0;
    }

  if (fatal)
    error (0, 0, "%s: Not enough room to add .dynamic entry",
	   dso->filename);
  return 1;
}

int
check_dso (DSO *dso)
{
  int i, last = 1;

  /* FIXME: Several routines in prelink and in libelf-0.7.0 too
     rely on sh_offset's monotonically increasing.  */
  for (i = 2; i < dso->ehdr.e_shnum; ++i)
    {
      if (dso->shdr[last].sh_offset
	  + (dso->shdr[last].sh_type == SHT_NOBITS
	     ? 0 : dso->shdr[last].sh_size) > dso->shdr[i].sh_offset)
	{
	  if (!dso->permissive
	      || RELOCATE_SCN (dso->shdr[last].sh_flags)
	      || RELOCATE_SCN (dso->shdr[i].sh_flags))
	    {
	      error (0, 0, "%s: section file offsets not monotonically increasing",
		     dso->filename);
	      return 1;
	    }
	}
      if (!dso->permissive
	  || (dso->shdr[i].sh_type != SHT_NOBITS && dso->shdr[i].sh_size != 0))
	last = i;
    }
  return 0;
}

DSO *
open_dso (const char *name)
{
  int fd;

  fd = open (name, O_RDONLY);
  if (fd == -1)
    {
      error (0, errno, "cannot open \"%s\"", name);
      return NULL;
    }
  return fdopen_dso (fd, name);
}

/* WARNING: If prelink is ever multi-threaded, this will not work
   Other alternatives are:
   1) make section_cmp nested function - trampolines
      vs. non-exec stack needs to be resolved for it though
   2) make the variable __thread
   3) use locking around the qsort
 */
static DSO *section_cmp_dso;

static int
section_cmp (const void *A, const void *B)
{
  int *a = (int *) A;
  int *b = (int *) B;
  DSO *dso = section_cmp_dso;

  if (dso->shdr[*a].sh_offset < dso->shdr[*b].sh_offset)
    return -1;
  if (dso->shdr[*a].sh_offset > dso->shdr[*b].sh_offset)
    return 1;
  if (*a < *b)
    return -1;
  return *a > *b;
}

DSO *
fdopen_dso (int fd, const char *name)
{
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  GElf_Addr last_off;
  int i, j, k, last, *sections, *invsections;
  DSO *dso = NULL;
  struct PLArch *plarch;
  extern struct PLArch __start_pl_arch[], __stop_pl_arch[];

  elf = elf_begin (fd, ELF_C_READ, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto error_out;
    }

  if (elf_kind (elf) != ELF_K_ELF)
    {
      error (0, 0, "\"%s\" is not an ELF file", name);
      goto error_out;
    }

  if (gelf_getehdr (elf, &ehdr) == NULL)
    {
      error (0, 0, "cannot get the ELF header: %s",
	     elf_errmsg (-1));
      goto error_out;
    }

  if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC)
    {
      error (0, 0, "\"%s\" is not a shared library", name);
      goto error_out;
    }

  if (ehdr.e_shnum == 0)
    {
      GElf_Phdr phdr;

      /* Check for UPX compressed executables.  */
      if (ehdr.e_type == ET_EXEC
	  && ehdr.e_phnum > 0
	  && (gelf_getphdr (elf, 0, &phdr), phdr.p_type == PT_LOAD)
	  && phdr.p_filesz >= 256
	  && phdr.p_filesz <= 4096
	  && phdr.p_offset == 0
	  && ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize < phdr.p_filesz)
	{
	  char *buf = alloca (phdr.p_filesz);
	  size_t start = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;

	  if (pread (fd, buf, phdr.p_filesz, 0) == phdr.p_filesz
	      && memmem (buf + start, phdr.p_filesz - start,
			 "UPX!", 4) != NULL)
	    {
	      error (0, 0, "\"%s\" is UPX compressed executable", name);
	      goto error_out;
	    }
	}
      error (0, 0, "\"%s\" has no section headers", name);
      goto error_out;
    }

  /* Allocate DSO structure. Leave place for additional 20 new section
     headers.  */
  dso = (DSO *)
	malloc (sizeof(DSO) + (ehdr.e_shnum + 20) * sizeof(GElf_Shdr)
		+ (ehdr.e_phnum + 1) * sizeof(GElf_Phdr)
		+ (ehdr.e_shnum + 20) * sizeof(Elf_Scn *));
  if (!dso)
    {
      error (0, ENOMEM, "Could not open DSO");
      goto error_out;
    }

  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT | ELF_F_PERMISSIVE);

  memset (dso, 0, sizeof(DSO));
  dso->elf = elf;
  dso->ehdr = ehdr;
  dso->phdr = (GElf_Phdr *) &dso->shdr[ehdr.e_shnum + 20];
  dso->scn = (Elf_Scn **) &dso->phdr[ehdr.e_phnum + 1];
  switch (ehdr.e_ident[EI_CLASS])
    {
    case ELFCLASS32:
      dso->mask = 0xffffffff; break;
    case ELFCLASS64:
      dso->mask = 0xffffffffffffffffULL; break;
    }
  for (i = 0; i < ehdr.e_phnum; ++i)
    gelf_getphdr (elf, i, dso->phdr + i);
  dso->fd = fd;

  for (i = 0, j = 0; i < ehdr.e_shnum; ++i)
    {
      dso->scn[i] = elf_getscn (elf, i);
      gelfx_getshdr (elf, dso->scn[i], dso->shdr + i);
      if ((dso->shdr[i].sh_flags & SHF_ALLOC) && dso->shdr[i].sh_type != SHT_NOBITS)
	j = 1;
    }
  if (j == 0)
    {
      /* If all ALLOC sections are SHT_NOBITS, then this is a
	 stripped-to-file debuginfo.  Skip it silently.  */
      goto error_out;
    }

  sections = (int *) alloca (dso->ehdr.e_shnum * sizeof (int) * 2);
  sections[0] = 0;
  for (i = 1, j = 1, k = dso->ehdr.e_shnum, last = -1;
       i < dso->ehdr.e_shnum; ++i)
    if (RELOCATE_SCN (dso->shdr[i].sh_flags))
      {
	last = i;
	sections[j++] = i;
      }
    else
      sections[--k] = i;
  assert (j == k);

  section_cmp_dso = dso;
  qsort (sections + k, dso->ehdr.e_shnum - k, sizeof (*sections), section_cmp);
  invsections = sections + dso->ehdr.e_shnum;
  invsections[0] = 0;
  for (i = 1, j = 0; i < ehdr.e_shnum; ++i)
    {
      if (i != sections[i])
	{
	  j = 1;
	  dso->scn[i] = elf_getscn (elf, sections[i]);
	  gelfx_getshdr (elf, dso->scn[i], dso->shdr + i);
	}
      invsections[sections[i]] = i;
    }

  if (j)
    {
      dso->move = init_section_move (dso);
      if (dso->move == NULL)
	goto error_out;
      memcpy (dso->move->old_to_new, invsections, dso->ehdr.e_shnum * sizeof (int));
      memcpy (dso->move->new_to_old, sections, dso->ehdr.e_shnum * sizeof (int));
    }

  last_off = 0;
  for (i = 1; i < ehdr.e_shnum; ++i)
    {
      if (dso->shdr[i].sh_link >= ehdr.e_shnum)
	{
	  error (0, 0, "%s: bogus sh_link value %d", name,
		 dso->shdr[i].sh_link);
	  goto error_out;
	}
      dso->shdr[i].sh_link = invsections[dso->shdr[i].sh_link];
      if (dso->shdr[i].sh_type == SHT_REL
	  || dso->shdr[i].sh_type == SHT_RELA
	  || (dso->shdr[i].sh_flags & SHF_INFO_LINK))
	{
	  if (dso->shdr[i].sh_info >= ehdr.e_shnum)
	    {
	      error (0, 0, "%s: bogus sh_info value %d", name,
		     dso->shdr[i].sh_info);
	      goto error_out;
	    }
	  dso->shdr[i].sh_info = invsections[dso->shdr[i].sh_info];
	}

      /* Some linkers mess up sh_offset fields for empty or nobits
	 sections.  */
      if (RELOCATE_SCN (dso->shdr[i].sh_flags)
	  && (dso->shdr[i].sh_size == 0
	      || dso->shdr[i].sh_type == SHT_NOBITS))
	{
	  for (j = i + 1; j < ehdr.e_shnum; ++j)
	    if (! RELOCATE_SCN (dso->shdr[j].sh_flags))
	      break;
	    else if (dso->shdr[j].sh_size != 0
		     && dso->shdr[j].sh_type != SHT_NOBITS)
	      break;
	  dso->shdr[i].sh_offset = (last_off + dso->shdr[i].sh_addralign - 1)
				   & ~(dso->shdr[i].sh_addralign - 1);
	  if (j < ehdr.e_shnum
	      && dso->shdr[i].sh_offset > dso->shdr[j].sh_offset)
	    {
	      GElf_Addr k;

	      for (k = dso->shdr[i].sh_addralign - 1; k; )
		{
		  k >>= 1;
		  dso->shdr[i].sh_offset = (last_off + k) & ~k;
		  if (dso->shdr[i].sh_offset <= dso->shdr[j].sh_offset)
		    break;
		}
	    }
	  last_off = dso->shdr[i].sh_offset;
	}
      else
	last_off = dso->shdr[i].sh_offset + dso->shdr[i].sh_size;
    }
  dso->ehdr.e_shstrndx = invsections[dso->ehdr.e_shstrndx];

  for (plarch = __start_pl_arch; plarch < __stop_pl_arch; plarch++)
    if (plarch->class == ehdr.e_ident[EI_CLASS]
	&& (plarch->machine == ehdr.e_machine
	    || plarch->alternate_machine[0] == ehdr.e_machine
	    || plarch->alternate_machine[1] == ehdr.e_machine
	    || plarch->alternate_machine[2] == ehdr.e_machine))
      break;

  if (plarch == __stop_pl_arch || ehdr.e_machine == EM_NONE)
    {
      error (0, 0, "\"%s\"'s architecture is not supported", name);
      goto error_out;
    }

  dso->arch = plarch;

  dso->base = ~(GElf_Addr) 0;
  dso->align = 0;
  dso->end = 0;
  for (i = 0; i < dso->ehdr.e_phnum; i++)
    if (dso->phdr[i].p_type == PT_LOAD)
      {
	GElf_Addr base, end;

	if (dso->phdr[i].p_align > dso->align)
	  dso->align = dso->phdr[i].p_align;
	base = dso->phdr[i].p_vaddr & ~(dso->phdr[i].p_align - 1);
	end = dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz;
	if (base < dso->base)
	  dso->base = base;
	if (end > dso->end)
	  dso->end = end;
      }

  if (dso->base == ~(GElf_Addr) 0)
    {
      error (0, 0, "%s: cannot find loadable segment", name);
      goto error_out;
    }

  read_dynamic (dso);

  dso->filename = (const char *) strdup (name);
  dso->soname = dso->filename;
  if (dso->info[DT_STRTAB] && dso->info[DT_SONAME])
    {
      const char *soname;

      soname = get_data (dso, dso->info[DT_STRTAB] + dso->info[DT_SONAME],
			 NULL);
      if (soname && soname[0] != '\0')
	dso->soname = (const char *) strdup (soname);
    }

  if (dso->arch->machine == EM_ALPHA
      || dso->arch->machine == EM_MIPS)
    for (i = 1; i < ehdr.e_shnum; ++i)
      {
	if ((dso->shdr[i].sh_type == SHT_ALPHA_DEBUG
	     && dso->arch->machine == EM_ALPHA)
	    || (dso->shdr[i].sh_type == SHT_MIPS_DEBUG
		&& dso->arch->machine == EM_MIPS))
	  {
	    const char *name
	      = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
	    if (! strcmp (name, ".mdebug"))
	      dso->mdebug_orig_offset = dso->shdr[i].sh_offset;
	    break;
	  }
      }

  return dso;

error_out:
  if (dso)
    {
      free (dso->move);
      if (dso->soname != dso->filename)
	free ((char *) dso->soname);
      free ((char *) dso->filename);
      free (dso);
    }
  if (elf)
    elf_end (elf);
  if (fd != -1)
    close (fd);
  return NULL;
}

static int
adjust_symtab_section_indices (DSO *dso, int n, int old_shnum, int *old_to_new)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Sym sym;
  int changed = 0, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getsym (dso->elf, data, ndx, &sym);
	  if (sym.st_shndx > SHN_UNDEF && sym.st_shndx < SHN_LORESERVE)
	    {
	      if (sym.st_shndx >= old_shnum
		  || old_to_new[sym.st_shndx] == -1)
		{
		  if (! sym.st_size &&
		      sym.st_info == ELF32_ST_INFO (STB_LOCAL, STT_SECTION))
		    {
		      sym.st_value = 0;
		      sym.st_shndx = SHN_UNDEF;
		      gelfx_update_sym (dso->elf, data, ndx, &sym);
		      changed = 1;
		      continue;
		    }
		  else
		    {
		      if (sym.st_shndx >= old_shnum)
			{
			  error (0, 0, "%s: Symbol section index outside of section numbers",
				 dso->filename);
			  return 1;
			}
		      error (0, 0, "%s: Section symbol points into has been removed",
			     dso->filename);
		      return 1;
		    }
		}
	      if (old_to_new[sym.st_shndx] != sym.st_shndx)
		{
		  changed = 1;
		  sym.st_shndx = old_to_new[sym.st_shndx];
		  gelfx_update_sym (dso->elf, data, ndx, &sym);
		}
	    }
	}
    }

  if (changed)
    elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);

  return 0;
}

static int
set_stt_section_values (DSO *dso, int n)
{
  Elf_Data *data;
  Elf_Scn *scn = dso->scn[n];
  GElf_Sym sym;
  int ndx, maxndx, sec;
  char seen[dso->ehdr.e_shnum];

  memset (seen, 0, dso->ehdr.e_shnum);
  data = elf_getdata (scn, NULL);
  assert (data != NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0);

  maxndx = data->d_size / dso->shdr[n].sh_entsize;
  gelfx_getsym (dso->elf, data, 0, &sym);
  if (sym.st_info != ELF32_ST_INFO (STB_LOCAL, STT_NOTYPE)
      || sym.st_size != 0 || sym.st_other != 0
      || sym.st_value != 0 || sym.st_shndx != SHN_UNDEF
      || sym.st_name != 0)
    return 0;

  for (ndx = 1; ndx < maxndx; ++ndx)
    {
      gelfx_getsym (dso->elf, data, ndx, &sym);
      if (sym.st_info == ELF32_ST_INFO (STB_LOCAL, STT_SECTION)
	  && sym.st_size == 0 && sym.st_other == 0
	  && sym.st_name == 0)
	{
	  if (sym.st_shndx > SHN_UNDEF && sym.st_shndx < SHN_LORESERVE)
	    {
	      seen[sym.st_shndx] = 1;
	      sym.st_value = dso->shdr[sym.st_shndx].sh_addr;
	      gelfx_update_sym (dso->elf, data, ndx, &sym);
	    }
	}
      else
	break;
    }

  for (ndx = 1, sec = 1; ndx < maxndx; ++ndx)
    {
      gelfx_getsym (dso->elf, data, ndx, &sym);
      if (sym.st_info == ELF32_ST_INFO (STB_LOCAL, STT_SECTION)
	  && sym.st_size == 0 && sym.st_other == 0
	  && sym.st_name == 0)
	{
	  if (sym.st_shndx == SHN_UNDEF)
	    {
	      while (sec < dso->ehdr.e_shnum && seen[sec])
		++sec;

	      if (sec >= dso->ehdr.e_shnum)
		sym.st_value = 0;
	      else
		sym.st_value = dso->shdr[sec].sh_addr;
	      sym.st_shndx = sec++;
	      gelfx_update_sym (dso->elf, data, ndx, &sym);
	    }
	}
      else
	break;
    }

  return 0;
}

struct section_move *
init_section_move (DSO *dso)
{
  struct section_move *move;
  int i;

  move = malloc (sizeof (struct section_move)
		 + (dso->ehdr.e_shnum * 2 + 20) * sizeof (int));
  if (move == NULL)
    {
      error (0, ENOMEM, "%s: Could not move sections", dso->filename);
      return move;
    }
  move->old_shnum = dso->ehdr.e_shnum;
  move->new_shnum = dso->ehdr.e_shnum;
  move->old_to_new = (int *)(move + 1);
  move->new_to_old = move->old_to_new + move->new_shnum;
  for (i = 0; i < move->new_shnum; i++)
    {
      move->old_to_new[i] = i;
      move->new_to_old[i] = i;
    }
  return move;
}

void
add_section (struct section_move *move, int sec)
{
  int i;

  assert (move->new_shnum < move->old_shnum + 20);
  assert (sec <= move->new_shnum);

  memmove (move->new_to_old + sec + 1, move->new_to_old + sec,
	   (move->new_shnum - sec) * sizeof (int));
  ++move->new_shnum;
  move->new_to_old[sec] = -1;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] >= sec)
      ++move->old_to_new[i];
}

void
remove_section (struct section_move *move, int sec)
{
  int i;

  assert (sec < move->new_shnum);

  memmove (move->new_to_old + sec, move->new_to_old + sec + 1,
	   (move->new_shnum - sec - 1) * sizeof (int));
  --move->new_shnum;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] == sec)
      move->old_to_new[i] = -1;
    else if (move->old_to_new[i] > sec)
      --move->old_to_new[i];
}

int
reopen_dso (DSO *dso, struct section_move *move, const char *temp_base)
{
  char filename[strlen (temp_base ? temp_base : dso->filename)
		+ sizeof ("/dev/shm/.#prelink#.XXXXXX")];
  int adddel = 0;
  int free_move = 0;
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  char *e_ident;
  int fd, i, j;

  if (move == NULL)
    {
      move = init_section_move (dso);
      if (move == NULL)
	return 1;
      free_move = 1;
    }
  else
    assert (dso->ehdr.e_shnum == move->old_shnum);

  if (temp_base == NULL)
    temp_base = dso->filename;
  sprintf (filename, "%s.#prelink#.XXXXXX", temp_base);

  fd = mkstemp (filename);
  if (fd == -1)
    {
      strcpy (filename, "/tmp/#prelink#.XXXXXX");
      fd = mkstemp (filename);
      if (fd == -1)
	{
	  strcpy (filename, "/dev/shm/#prelink#.XXXXXX");
	  fd = mkstemp (filename);
	}
      if (fd == -1)
	{
	  error (0, errno, "Could not create temporary file %s", filename);
	  goto error_out;
	}
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto error_out;

    }

  /* Some gelf_newehdr implementations don't return the resulting
     ElfNN_Ehdr, so we have to do it the hard way instead of:
     e_ident = (char *) gelf_newehdr (elf, gelf_getclass (dso->elf));  */
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      e_ident = (char *) elf32_newehdr (elf);
      break;
    case ELFCLASS64:
      e_ident = (char *) elf64_newehdr (elf);
      break;
    default:
      e_ident = NULL;
      break;
    }

  if (e_ident == NULL
      /* This is here just for the gelfx wrapper, so that gelf_update_ehdr
	 already has the correct ELF class.  */
      || memcpy (e_ident, dso->ehdr.e_ident, EI_NIDENT) == NULL
      || gelf_update_ehdr (elf, &dso->ehdr) == 0
      || gelf_newphdr (elf, dso->ehdr.e_phnum) == 0)
    {
      error (0, 0, "Could not create new ELF headers");
      goto error_out;
    }
  ehdr = dso->ehdr;
  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT | ELF_F_PERMISSIVE);
  for (i = 0; i < ehdr.e_phnum; ++i)
    gelf_update_phdr (elf, i, dso->phdr + i);

  for (i = 1; i < move->new_shnum; ++i)
    {
      Elf_Scn *scn;
      Elf_Data data, *data1, *data2;

      if (move->new_to_old[i] == -1)
	{
	  scn = elf_newscn (elf);
	  elf_newdata (scn);
	}
      else
	{
	  j = move->new_to_old[i];
	  scn = elf_newscn (elf);
	  gelfx_update_shdr (elf, scn, &dso->shdr[j]);
	  if (dso->shdr[j].sh_type == SHT_NOBITS)
	    {
	       data1 = elf_getdata (dso->scn[j], NULL);
	       data2 = elf_newdata (scn);
	       memcpy (data2, data1, sizeof (*data1));
	    }
	  else
	    {
	      data.d_type = ELF_T_NUM;
	      data1 = NULL;
	      while ((data1 = elf_getdata (dso->scn[j], data1))
		     != NULL)
		{
		  if (data.d_type == ELF_T_NUM)
		    data = *data1;
		  else if (data.d_type != data1->d_type
			   || data.d_version != data1->d_version)
		    abort ();
		  else
		    {
		      if (data1->d_off < data.d_off)
			{
			  data.d_size += data.d_off - data1->d_off;
			  data.d_off = data1->d_off;
			}
		      if (data1->d_off + data1->d_size
			  > data.d_off + data.d_size)
			data.d_size = data1->d_off + data1->d_size
				      - data.d_off;
		      if (data1->d_align > data.d_align)
			data.d_align = data1->d_align;
		    }
		}
	      if (data.d_type == ELF_T_NUM)
		{
		  assert (dso->shdr[j].sh_size == 0);
		  continue;
		}
	      if (data.d_size != 0)
		{
		  data.d_buf = calloc (1, data.d_size);
		  if (data.d_buf == NULL)
		    {
		      error (0, ENOMEM, "%s: Could not copy section",
			     dso->filename);
		      goto error_out;
		    }
		}
	      else
		data.d_buf = NULL;
	      data1 = NULL;
	      while ((data1 = elf_getdata (dso->scn[j], data1))
		     != NULL)
		memcpy (data.d_buf + data1->d_off - data.d_off, data1->d_buf,
			data1->d_size);
	      data2 = elf_newdata (scn);
	      memcpy (data2, &data, sizeof (data));
	    }
	}
    }

  ehdr.e_shnum = move->new_shnum;
  dso->temp_filename = strdup (filename);
  if (dso->temp_filename == NULL)
    {
      error (0, ENOMEM, "%s: Could not save temporary filename", dso->filename);
      goto error_out;
    }
  dso->elfro = dso->elf;
  dso->elf = elf;
  dso->fdro = dso->fd;
  dso->fd = fd;
  dso->ehdr = ehdr;
  dso->lastscn = 0;
  elf = NULL;
  fd = -1;
  for (i = 1; i < move->old_shnum; i++)
    if (move->old_to_new[i] != i)
      {
	adddel = 1;
	break;
      }
  if (! adddel)
    for (i = 1; i < move->new_shnum; i++)
      if (move->new_to_old[i] != i)
	{
	  adddel = 1;
	  break;
	}

  for (i = 1; i < move->new_shnum; i++)
    {
      dso->scn[i] = elf_getscn (dso->elf, i);
      gelfx_getshdr (dso->elf, dso->scn[i], dso->shdr + i);
      if (move->new_to_old[i] == -1)
	continue;
      if (dso->move
	  && (dso->shdr[i].sh_type == SHT_SYMTAB
	      || dso->shdr[i].sh_type == SHT_DYNSYM))
	{
	  if (adjust_symtab_section_indices (dso, i, dso->move->old_shnum,
					     dso->move->old_to_new))
	    goto error_out;
	}
      if (adddel)
	{
	  if (dso->shdr[i].sh_link)
	    {
	      if (dso->shdr[i].sh_link >= move->old_shnum)
		{
		  error (0, 0, "%s: bogus sh_link value %d", dso->filename,
			 dso->shdr[i].sh_link);
		  goto error_out;
		}
	      if (move->old_to_new[dso->shdr[i].sh_link] == -1)
		{
		  error (0, 0, "Section sh_link points to has been removed");
		  goto error_out;
		}
	      dso->shdr[i].sh_link = move->old_to_new[dso->shdr[i].sh_link];
	    }
	  /* Only some section types use sh_info for section index.  */
	  if (dso->shdr[i].sh_info
	      && (dso->shdr[i].sh_type == SHT_REL
		  || dso->shdr[i].sh_type == SHT_RELA
		  || (dso->shdr[i].sh_flags & SHF_INFO_LINK)))
	    {
	      if (dso->shdr[i].sh_info >= move->old_shnum)
		{
		  error (0, 0, "%s: bogus sh_info value %d", dso->filename,
			 dso->shdr[i].sh_info);
		  goto error_out;
		}
	      if (move->old_to_new[dso->shdr[i].sh_info] == -1)
		{
		  error (0, 0, "Section sh_info points to has been removed");
		  goto error_out;
		}
	      dso->shdr[i].sh_info = move->old_to_new[dso->shdr[i].sh_info];
	    }
	  if (dso->shdr[i].sh_type == SHT_SYMTAB
	      || dso->shdr[i].sh_type == SHT_DYNSYM)
	    {
	      if (adjust_symtab_section_indices (dso, i, move->old_shnum,
						 move->old_to_new))
		goto error_out;
	    }
	}
    }

  free (dso->move);
  dso->move = NULL;

  dso->ehdr.e_shstrndx = move->old_to_new[dso->ehdr.e_shstrndx];
  gelf_update_ehdr (dso->elf, &dso->ehdr);

  read_dynamic (dso);

  /* If shoff does not point after last section, we need to adjust the sections
     after it if we added or removed some sections.  */
  if (move->old_shnum != move->new_shnum
      && adjust_dso_nonalloc (dso, 0, dso->ehdr.e_shoff + 1,
			      ((long) move->new_shnum - (long) move->old_shnum)
			      * gelf_fsize (dso->elf, ELF_T_SHDR, 1,
					    EV_CURRENT)))
    goto error_out;

  if (free_move)
    free (move);
  return 0;

error_out:
  if (free_move)
    free (move);
  if (elf)
    elf_end (elf);
  if (fd != -1)
    {
      unlink (filename);
      close (fd);
    }
  return 1;
}

/* Return true if the value of symbol SYM, which belongs to DSO,
   should be treated as an address within the DSO, and should
   therefore track DSO's relocations.  */

int
adjust_symbol_p (DSO *dso, GElf_Sym *sym)
{
  if (sym->st_shndx == SHN_ABS
      && sym->st_value != 0
      && GELF_ST_TYPE (sym->st_info) <= STT_FUNC)
    /* This is problematic.  How do we find out if
       we should relocate this?  Assume we should.  */
    return 1;

  return (sym->st_shndx > SHN_UNDEF
	  && sym->st_shndx < dso->ehdr.e_shnum
	  && ELF32_ST_TYPE (sym->st_info) != STT_TLS
	  && RELOCATE_SCN (dso->shdr[sym->st_shndx].sh_flags));
}

static int
adjust_symtab (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Sym sym;
  int ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getsym (dso->elf, data, ndx, &sym);
	  if (adjust_symbol_p (dso, &sym) && sym.st_value >= start)
	    {
	      sym.st_value += adjust;
	      gelfx_update_sym (dso->elf, data, ndx, &sym);
	    }
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
dso_is_rdwr (DSO *dso)
{
  return dso->elfro != NULL;
}

GElf_Addr
adjust_old_to_new (DSO *dso, GElf_Addr addr)
{
  int i;

  if (dso->adjust == NULL)
    return addr; /* Fast path.  */

  for (i = 0; i < dso->nadjust; i++)
    if (addr >= dso->adjust[i].start)
      {
	addr += dso->adjust[i].adjust;
	assert (dso->ehdr.e_ident[EI_CLASS] != ELFCLASS32
		|| addr == (Elf32_Addr) addr);
	return addr;
      }

  return addr;
}

GElf_Addr
adjust_new_to_old (DSO *dso, GElf_Addr addr)
{
  int i;

  if (dso->adjust == NULL)
    return addr; /* Fast path.  */

  for (i = 0; i < dso->nadjust; i++)
    if (addr >= dso->adjust[i].start + dso->adjust[i].adjust)
      {
	addr -= dso->adjust[i].adjust;
	assert (dso->ehdr.e_ident[EI_CLASS] != ELFCLASS32
		|| addr == (Elf32_Addr) addr);
	return addr;
      }

  return addr;
}

static int
adjust_dynamic (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Dyn dyn;
  int ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getdyn (dso->elf, data, ndx, &dyn);
	  if (dso->arch->adjust_dyn (dso, n, &dyn, start, adjust) == 0)
	    switch (dyn.d_tag)
	      {
	      case DT_REL:
	      case DT_RELA:
		/* On some arches DT_REL* may be 0 indicating no relocations
		   (if DT_REL*SZ is also 0).  Don't adjust it in that case.  */
		if (dyn.d_un.d_ptr && dyn.d_un.d_ptr >= start)
		  {
		    dyn.d_un.d_ptr += adjust;
		    gelfx_update_dyn (dso->elf, data, ndx, &dyn);
		  }
		break;
	      default:
		if (dyn.d_tag < DT_ADDRRNGLO || dyn.d_tag > DT_ADDRRNGHI)
		  break;
		/* FALLTHROUGH */
	      case DT_INIT:
	      case DT_FINI:
	      case DT_HASH:
	      case DT_STRTAB:
	      case DT_SYMTAB:
	      case DT_JMPREL:
	      case DT_INIT_ARRAY:
	      case DT_FINI_ARRAY:
	      case DT_PREINIT_ARRAY:
	      case DT_VERDEF:
	      case DT_VERNEED:
	      case DT_VERSYM:
	      case DT_PLTGOT:
		if (dyn.d_un.d_ptr >= start)
		  {
		    dyn.d_un.d_ptr += adjust;
		    gelfx_update_dyn (dso->elf, data, ndx, &dyn);
		  }
		break;
	      }
	  else
	    gelfx_update_dyn (dso->elf, data, ndx, &dyn);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);

  /* Update the cached dynamic info as well.  */
  read_dynamic (dso);
  return 0;
}

int
addr_to_sec (DSO *dso, GElf_Addr addr)
{
  GElf_Shdr *shdr;
  int i;

  shdr = &dso->shdr[dso->lastscn];
  for (i = -1; i < dso->ehdr.e_shnum; shdr = &dso->shdr[++i])
    if (RELOCATE_SCN (shdr->sh_flags)
	&& shdr->sh_addr <= addr && shdr->sh_addr + shdr->sh_size > addr
	&& (shdr->sh_type != SHT_NOBITS || (shdr->sh_flags & SHF_TLS) == 0))
      {
	if (i != -1)
	  dso->lastscn = i;
	return dso->lastscn;
      }

  return -1;
}

static int
adjust_rel (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
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

	  dso->arch->adjust_rel (dso, &rel, start, adjust);
	  addr_adjust (rel.r_offset, start, adjust);
	  gelfx_update_rel (dso->elf, data, ndx, &rel);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

static int
adjust_rela (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  GElf_Rela rela;
  int sec, ndx, maxndx;

  while ((data = elf_getdata (scn, data)) != NULL)
    {
      maxndx = data->d_size / dso->shdr[n].sh_entsize;
      for (ndx = 0; ndx < maxndx; ++ndx)
	{
	  gelfx_getrela (dso->elf, data, ndx, &rela);
	  sec = addr_to_sec (dso, rela.r_offset);
	  if (sec == -1)
	    continue;

	  dso->arch->adjust_rela (dso, &rela, start, adjust);
	  addr_adjust (rela.r_offset, start, adjust);
	  gelfx_update_rela (dso->elf, data, ndx, &rela);
	}
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}

int
adjust_nonalloc (DSO *dso, GElf_Ehdr *ehdr, GElf_Shdr *shdr, int first,
		 GElf_Addr start, GElf_Addr adjust)
{
  int i;

  for (i = 1; i < ehdr->e_shnum; i++)
    {
      if (RELOCATE_SCN (shdr[i].sh_flags) || shdr[i].sh_type == SHT_NULL)
	continue;

      if ((shdr[i].sh_offset > start
	   || (shdr[i].sh_offset == start && i >= first))
	  && (adjust & (shdr[i].sh_addralign - 1)))
	adjust = (adjust + shdr[i].sh_addralign - 1)
		 & ~(shdr[i].sh_addralign - 1);
    }

  if (ehdr->e_shoff >= start)
    {
      GElf_Addr shdralign = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);

      if (adjust & (shdralign - 1))
	adjust = (adjust + shdralign - 1) & ~(shdralign - 1);
      ehdr->e_shoff += adjust;
    }

  for (i = 1; i < ehdr->e_shnum; i++)
    {
      if (RELOCATE_SCN (shdr[i].sh_flags) || shdr[i].sh_type == SHT_NULL)
	continue;

      if (shdr[i].sh_offset > start
	  || (shdr[i].sh_offset == start && i >= first))
	shdr[i].sh_offset += adjust;
    }
  return 0;
}

int
adjust_dso_nonalloc (DSO *dso, int first, GElf_Addr start, GElf_Addr adjust)
{
  return adjust_nonalloc (dso, &dso->ehdr, dso->shdr, first, start, adjust);
}

/* Add ADJUST to all addresses above START.  */
int
adjust_dso (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  int i;

  if (dso->ehdr.e_entry >= start)
    {
      dso->ehdr.e_entry += adjust;
      gelf_update_ehdr (dso->elf, &dso->ehdr);
      elf_flagehdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);
    }

  for (i = 0; i < dso->ehdr.e_phnum; i++)
    {
      /* Leave STACK segment alone, it has
	 p_vaddr == p_paddr == p_offset == p_filesz == p_memsz == 0.  */
      if (dso->phdr[i].p_type == PT_GNU_STACK)
	continue;
      if (! start)
	{
	  dso->phdr[i].p_vaddr += adjust;
	  dso->phdr[i].p_paddr += adjust;
	}
      else if (start <= dso->phdr[i].p_vaddr)
	{
	  dso->phdr[i].p_vaddr += adjust;
	  dso->phdr[i].p_paddr += adjust;
	  dso->phdr[i].p_offset += adjust;
	}
      else if (start < dso->phdr[i].p_vaddr + dso->phdr[i].p_filesz)
	{
	  dso->phdr[i].p_filesz += adjust;
	  dso->phdr[i].p_memsz += adjust;
	}
      else if (start < dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz)
	dso->phdr[i].p_memsz += adjust;
      else
	continue;
      if (dso->phdr[i].p_type == PT_LOAD
	  && (dso->phdr[i].p_vaddr - dso->phdr[i].p_offset)
	     % dso->phdr[i].p_align)
	{
	  error (0, 0, "%s: PT_LOAD %08llx %08llx 0x%x would be not properly aligned",
		 dso->filename, (long long) dso->phdr[i].p_offset,
		 (long long) dso->phdr[i].p_vaddr, (int) dso->phdr[i].p_align);
	  return 1;
	}
      gelf_update_phdr (dso->elf, i, dso->phdr + i);
    }
  elf_flagphdr (dso->elf, ELF_C_SET, ELF_F_DIRTY);

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    {
      const char *name;

      if (dso->arch->adjust_section)
	{
	  int ret = dso->arch->adjust_section (dso, i, start, adjust);

	  if (ret == 1)
	    return 1;
	  else if (ret)
	    continue;
	}
      switch (dso->shdr[i].sh_type)
	{
	case SHT_PROGBITS:
	  name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name);
	  if (strcmp (name, ".stab") == 0
	      && adjust_stabs (dso, i, start, adjust))
	    return 1;
	  if (strcmp (name, ".debug_info") == 0
	      && adjust_dwarf2 (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_HASH:
	case SHT_GNU_HASH:
	case SHT_NOBITS:
	case SHT_STRTAB:
	  break;
	case SHT_SYMTAB:
	case SHT_DYNSYM:
	  if (adjust_symtab (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_DYNAMIC:
	  if (adjust_dynamic (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_REL:
	  if (adjust_rel (dso, i, start, adjust))
	    return 1;
	  break;
	case SHT_RELA:
	  if (adjust_rela (dso, i, start, adjust))
	    return 1;
	  break;
	}
      if ((dso->arch->machine == EM_ALPHA
	   && dso->shdr[i].sh_type == SHT_ALPHA_DEBUG)
	  || (dso->arch->machine == EM_MIPS
	      && dso->shdr[i].sh_type == SHT_MIPS_DEBUG))
	if (adjust_mdebug (dso, i, start, adjust))
	  return 1;
    }

  for (i = 0; i < dso->ehdr.e_shnum; i++)
    {
      if (RELOCATE_SCN (dso->shdr[i].sh_flags))
	{
	  if (dso->shdr[i].sh_addr >= start)
	    {
	      Elf_Scn *scn = dso->scn[i];

	      dso->shdr[i].sh_addr += adjust;
	      if (start)
		dso->shdr[i].sh_offset += adjust;
	      gelfx_update_shdr (dso->elf, scn, dso->shdr + i);
	      elf_flagshdr (scn, ELF_C_SET, ELF_F_DIRTY);
	    }
	}
    }

  addr_adjust (dso->base, start, adjust);
  addr_adjust (dso->end, start, adjust);

  if (start)
    {
      start = adjust_new_to_old (dso, start);
      for (i = 0; i < dso->nadjust; i++)
	if (start < dso->adjust[i].start)
	  dso->adjust[i].adjust += adjust;
	else
	  break;
      if (i < dso->nadjust && start == dso->adjust[i].start)
	dso->adjust[i].adjust += adjust;
      else
	{
	  dso->adjust =
	    realloc (dso->adjust, (dso->nadjust + 1) * sizeof (*dso->adjust));
	  if (dso->adjust == NULL)
	    {
	      error (0, ENOMEM, "Cannot record the list of adjustements being made");
	      return 1;
	    }
	  memmove (dso->adjust + i + 1, dso->adjust + i, dso->nadjust - i);
	  dso->adjust[i].start = start;
	  dso->adjust[i].adjust = adjust;
	  ++dso->nadjust;
	}
    }

  return start ? adjust_dso_nonalloc (dso, 0, 0, adjust) : 0;
}

int
recompute_nonalloc_offsets (DSO *dso)
{
  int i, first_nonalloc, sec_before_shoff = 0;
  GElf_Addr last_offset = 0;
  GElf_Addr shdralign = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
  GElf_Addr shdrsize = gelf_fsize (dso->elf, ELF_T_SHDR, 1, EV_CURRENT)
		       * dso->ehdr.e_shnum;

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    if (RELOCATE_SCN (dso->shdr[i].sh_flags))
      {
	if (dso->shdr[i].sh_type == SHT_NOBITS)
	  last_offset = dso->shdr[i].sh_offset;
	else
	  last_offset = dso->shdr[i].sh_offset + dso->shdr[i].sh_size;
      }
    else
      break;

  first_nonalloc = i;
  if (dso->ehdr.e_shoff < dso->shdr[i].sh_offset)
    {
      dso->ehdr.e_shoff = (last_offset + shdralign - 1) & ~(shdralign - 1);
      last_offset = dso->ehdr.e_shoff + shdrsize;
    }
  else
    for (; i < dso->ehdr.e_shnum; ++i)
      if (dso->shdr[i].sh_offset < dso->ehdr.e_shoff
	  && (i == dso->ehdr.e_shnum - 1
	      || dso->shdr[i + 1].sh_offset > dso->ehdr.e_shoff))
	{
	  sec_before_shoff = i;
	  break;
	}

  for (i = first_nonalloc; i < dso->ehdr.e_shnum; ++i)
    {
      assert (!RELOCATE_SCN (dso->shdr[i].sh_flags));
      assert (dso->shdr[i].sh_type != SHT_NOBITS);
      dso->shdr[i].sh_offset = (last_offset + dso->shdr[i].sh_addralign - 1)
			       & ~(dso->shdr[i].sh_addralign - 1);
      last_offset = dso->shdr[i].sh_offset + dso->shdr[i].sh_size;
      if (i == sec_before_shoff)
	{
	  dso->ehdr.e_shoff = (last_offset + shdralign - 1) & ~(shdralign - 1);
	  last_offset = dso->ehdr.e_shoff + shdrsize;
	}
    }

  return 0;
}

int
strtabfind (DSO *dso, int strndx, const char *name)
{
  Elf_Scn *scn;
  Elf_Data *data;
  const char *p, *q, *r;
  size_t len = strlen (name);

  if (dso->shdr[strndx].sh_type != SHT_STRTAB)
    return 0;

  scn = dso->scn[strndx];
  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0);
  assert (data->d_size == dso->shdr[strndx].sh_size);
  q = data->d_buf + data->d_size;
  for (p = data->d_buf; p < q; p = r + 1)
    {
      r = strchr (p, '\0');
      if (r - p >= len && memcmp (r - len, name, len) == 0)
	return (r - (const char *) data->d_buf) - len;
    }

  return 0;
}

int
shstrtabadd (DSO *dso, const char *name)
{
  Elf_Scn *scn;
  Elf_Data *data;
  GElf_Addr adjust;
  const char *p, *q, *r;
  size_t len = strlen (name), align;
  int ret;

  scn = dso->scn[dso->ehdr.e_shstrndx];
  data = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0);
  assert (data->d_size == dso->shdr[dso->ehdr.e_shstrndx].sh_size);
  q = data->d_buf + data->d_size;
  for (p = data->d_buf; p < q; p = r + 1)
    {
      r = strchr (p, '\0');
      if (r - p >= len && memcmp (r - len, name, len) == 0)
	return (r - (const char *) data->d_buf) - len;
    }

  data->d_buf = realloc (data->d_buf, data->d_size + len + 1);
  if (data->d_buf == NULL)
    {
      error (0, ENOMEM, "Cannot add new section name %s", name);
      return 0;
    }

  memcpy (data->d_buf + data->d_size, name, len + 1);
  ret = data->d_size;
  data->d_size += len + 1;
  align = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
  adjust = (len + 1 + align - 1) & ~(align - 1);
  if (adjust_dso_nonalloc (dso, 0,
			   dso->shdr[dso->ehdr.e_shstrndx].sh_offset
			   + dso->shdr[dso->ehdr.e_shstrndx].sh_size,
			   adjust))
    return 0;
  dso->shdr[dso->ehdr.e_shstrndx].sh_size += len + 1;
  return ret;
}

int
relocate_dso (DSO *dso, GElf_Addr base)
{
  /* Check if it is already relocated.  */
  if (dso->base == base)
    return 0;

  if (! dso_is_rdwr (dso))
    {
      if (reopen_dso (dso, NULL, NULL))
	return 1;
    }

  return adjust_dso (dso, 0, base - dso->base);
}

static int
close_dso_1 (DSO *dso)
{
  if (dso_is_rdwr (dso))
    {
      int i;

      for (i = 1; i < dso->ehdr.e_shnum; ++i)
	{
	  Elf_Scn *scn = dso->scn[i];
	  Elf_Data *data = NULL;

	  while ((data = elf_getdata (scn, data)) != NULL)
	    {
	      free (data->d_buf);
	      data->d_buf = NULL;
	    }
	}
    }

  elf_end (dso->elf);
  close (dso->fd);
  if (dso->elfro)
    {
      elf_end (dso->elfro);
      close (dso->fdro);
    }
  if (dso->filename != dso->soname)
    free ((char *) dso->soname);
  free ((char *) dso->filename);
  free ((char *) dso->temp_filename);
  free (dso->move);
  free (dso->adjust);
  free (dso->undo.d_buf);
  free (dso);
  return 0;
}

int
close_dso (DSO *dso)
{
  int rdwr = dso_is_rdwr (dso);

  if (rdwr && dso->temp_filename != NULL)
    unlink (dso->temp_filename);
  close_dso_1 (dso);
  return 0;
}

int
prepare_write_dso (DSO *dso)
{
  int i;

  if (check_dso (dso)
      || (dso->mdebug_orig_offset && finalize_mdebug (dso)))
    return 1;

  gelf_update_ehdr (dso->elf, &dso->ehdr);
  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    gelf_update_phdr (dso->elf, i, dso->phdr + i);
  for (i = 0; i < dso->ehdr.e_shnum; ++i)
    {
      gelfx_update_shdr (dso->elf, dso->scn[i], dso->shdr + i);
      if (dso->shdr[i].sh_type == SHT_SYMTAB
	  || dso->shdr[i].sh_type == SHT_DYNSYM)
	set_stt_section_values (dso, i);
    }
  return 0;
}

int
write_dso (DSO *dso)
{
  if (prepare_write_dso (dso))
    return 1;

  if (! dso->permissive && ELF_F_PERMISSIVE)
    elf_flagelf (dso->elf, ELF_C_CLR, ELF_F_PERMISSIVE);

  if (elf_update (dso->elf, ELF_C_WRITE) == -1)
    return 2;
  return 0;
}

int
set_security_context (DSO *dso, const char *temp_name, const char *name)
{
#ifdef USE_SELINUX
  static int selinux_enabled = -1;
  if (selinux_enabled == -1)
    selinux_enabled = is_selinux_enabled ();
  if (selinux_enabled > 0)
    {
      security_context_t scontext;
      if (getfilecon (name, &scontext) < 0)
	{
	  /* If the filesystem doesn't support extended attributes,
	     the original had no special security context and the
	     target cannot have one either.  */
	  if (errno == EOPNOTSUPP)
	    return 0;

	  error (0, errno, "Could not get security context for %s",
		 name);
	  return 1;
	}
      if (setfilecon (temp_name, scontext) < 0)
	{
	  error (0, errno, "Could not set security context for %s",
		 name);
	  freecon (scontext);
	  return 1;
	}
      freecon (scontext);
    }
#endif
  return 0;
}

int
update_dso (DSO *dso, const char *orig_name)
{
  int rdwr = dso_is_rdwr (dso);

  if (rdwr)
    {
      char *name1, *name2;
      struct utimbuf u;
      struct stat64 st;

      switch (write_dso (dso))
	{
	case 2:
	  error (0, 0, "Could not write %s: %s", dso->filename,
		 elf_errmsg (-1));
	  /* FALLTHROUGH */
	case 1:
	  close_dso (dso);
	  return 1;
	case 0:
	  break;
	}

      name1 = strdupa (dso->filename);
      name2 = strdupa (dso->temp_filename);
      if (fstat64 (dso->fdro, &st) < 0)
	{
	  error (0, errno, "Could not stat %s", dso->filename);
	  close_dso (dso);
	  return 1;
	}
      if (fchown (dso->fd, st.st_uid, st.st_gid) < 0
	  || fchmod (dso->fd, st.st_mode & 07777) < 0)
	{
	  error (0, errno, "Could not set %s owner or mode", dso->filename);
	  close_dso (dso);
	  return 1;
	}
      close_dso_1 (dso);
      u.actime = time (NULL);
      u.modtime = st.st_mtime;
      utime (name2, &u);

      if (set_security_context (dso, name2, orig_name ? orig_name : name1))
	{
	  unlink (name2);
	  return 1;
	}

      if (rename (name2, name1))
	{
	  unlink (name2);
	  error (0, errno, "Could not rename temporary to %s", name1);
	  return 1;
	}
    }
  else
    close_dso_1 (dso);

  return 0;
}
