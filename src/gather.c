/* Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Red Hat, Inc.
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
#include <fnmatch.h>
#include <ftw.h>
#include <glob.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prelinktab.h"
#include "reloc.h"

#ifndef HAVE_FTW_ACTIONRETVAL
# define FTW_ACTIONRETVAL	0
# define FTW_CONTINUE		0
# define FTW_STOP		1
#endif

static int gather_lib (struct prelink_entry *ent);
static int implicit;

static struct prelink_dir *dirs;
static struct prelink_dir *blacklist;
#ifndef HAVE_FTW_ACTIONRETVAL
static char *blacklist_dir;
static size_t blacklist_dir_len;
#endif
static struct extension
{
  const char *ext;
  size_t len;
  int is_glob;
} *blacklist_ext;
static int blacklist_next;

static int
gather_deps (DSO *dso, struct prelink_entry *ent)
{
  int i, j, seen = 0;
  FILE *f = NULL;
  const char *argv[5];
  const char *envp[4];
  char *line = NULL, *p, *q = NULL;
  const char **depends = NULL;
  size_t ndepends = 0, ndepends_alloced = 0;
  size_t len = 0;
  ssize_t n;
  Elf_Scn *scn;
  Elf_Data *data;
  Elf32_Lib *liblist = NULL;
  int nliblist = 0;
  const char *dl;
  const char *ent_filename;

  if (check_dso (dso))
    {
      if (! undo)
	ent->type = ET_UNPRELINKABLE;
      goto error_out;
    }

  ent->pltgot = dso->info[DT_PLTGOT];
  ent->soname = strdup (dso->soname);
  ent->flags = (dso->arch->class == ELFCLASS64 ? PCF_ELF64 : 0)
	       | (dso->arch->machine & PCF_MACHINE);
  if (ent->soname == NULL)
    {
      error (0, ENOMEM, "%s: Could not record SONAME", ent->filename);
      goto error_out;
    }

  dl = dynamic_linker ?: dso->arch->dynamic_linker;
  if (strcmp (dso->filename, dl) == 0
      || is_ldso_soname (dso->soname))
    {
      if (dynamic_info_is_set (dso, DT_GNU_PRELINKED_BIT)
	  && dynamic_info_is_set (dso, DT_CHECKSUM_BIT))
	{
	  if (! undo && dso->arch->read_opd)
	    dso->arch->read_opd (dso, ent);
	  ent->done = 2;
	}
      close_dso (dso);
      return 0;
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name;
      if (dso->shdr[i].sh_type == SHT_GNU_LIBLIST
	  && (name = strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[i].sh_name))
	  && ! strcmp (name, ".gnu.liblist")
	  && (dso->shdr[i].sh_size % sizeof (Elf32_Lib)) == 0)
	{
	  nliblist = dso->shdr[i].sh_size / sizeof (Elf32_Lib);
	  liblist = (Elf32_Lib *) alloca (dso->shdr[i].sh_size);
	  scn = dso->scn[i];
	  data = elf_getdata (scn, NULL);
	  if (data == NULL || elf_getdata (scn, data)
	      || data->d_buf == NULL || data->d_off
	      || data->d_size != dso->shdr[i].sh_size)
	    liblist = NULL;
	  else
	    memcpy (liblist, data->d_buf, dso->shdr[i].sh_size);
	  if (! undo)
	    break;
	}
      else if (undo
	       && dso->shdr[i].sh_type == SHT_PROGBITS
	       && (name = strptr (dso, dso->ehdr.e_shstrndx,
				  dso->shdr[i].sh_name))
	       && ! strcmp (name, ".gnu.prelink_undo"))
	ent->done = 2;
    }

  if (! undo && dso->arch->read_opd)
    dso->arch->read_opd (dso, ent);
  close_dso (dso);
  dso = NULL;

  i = 0;
  argv[i++] = dl;
  if (ld_library_path)
    {
      argv[i++] = "--library-path";
      argv[i++] = ld_library_path;
    }
  if (strchr (ent->filename, '/') != NULL)
    ent_filename = ent->filename;
  else
    {
      size_t flen = strlen (ent->filename);
      char *tp = alloca (2 + flen + 1);
      memcpy (tp, "./", 2);
      memcpy (tp + 2, ent->filename, flen + 1);
      ent_filename = tp;
    }
  argv[i++] = ent_filename;
  argv[i] = NULL;
  envp[0] = "LD_TRACE_LOADED_OBJECTS=1";
  envp[1] = "LD_TRACE_PRELINKING=1";
  envp[2] = "LD_WARN=";
  envp[3] = NULL;
  f = execve_open (dl, (char * const *)argv, (char * const *)envp);
  if (f == NULL)
    goto error_out;

  do
    {
      n = getline (&line, &len, f);
      if (n < 0)
	break;

      if (line[n - 1] == '\n')
	line[n - 1] = '\0';

      p = strstr (line, " => ");
      if (p)
	{
	  q = strstr (p, " (");
	  if (q == NULL && strcmp (p, " => not found") == 0)
	    {
	      error (0, 0, "%s: Could not find one of the dependencies",
		     ent->filename);
	      goto error_out;
	    }
	}
      if (p == NULL || q == NULL)
	{
	  if (strstr (line, "statically linked") != NULL)
	    error (0, 0, "%s: Library without dependencies", ent->filename);
	  else
	    {
	      p = strstr (line, "error while loading shared libraries: ");
	      if (p != NULL)
		{
		  p += sizeof "error while loading shared libraries: " - 1;
		  q = strstr (line, "cannot open shared object file: "
				    "No such file or directory");
		  if (q != NULL)
		    {
		      error (0, 0,
			     "%s: Could not find one of the dependencies",
			     ent->filename);
		      goto error_out;
		    }
		}
	      error (0, 0, "%s: Could not parse `%s'", ent->filename, line);
	    }
	  goto error_out;
	}

      *p = '\0';
      p += sizeof " => " - 1;
      *q = '\0';
      if (! strcmp (p, ent_filename))
	{
	  ++seen;
	  continue;
	}
      if (ndepends == ndepends_alloced)
	{
	  ndepends_alloced += 10;
	  depends =
	    (const char **) realloc (depends,
				     ndepends_alloced * sizeof (char *));
	  if (depends == NULL)
	    {
	      error (0, ENOMEM, "%s: Could not record dependencies",
		     ent->filename);
	      goto error_out;
	    }
	}

      depends[ndepends] = strdupa (p);
      ++ndepends;
    } while (!feof (f));

  if (execve_close (f))
    {
      f = NULL;
      error (0, 0, "%s: Dependency tracing failed", ent->filename);
      goto error_out;
    }

  f = NULL;
  if (seen != 1)
    {
      error (0, 0, "%s seen %d times in LD_TRACE_PRELINKING output, expected once",
	     ent->filename, seen);
      goto error_out;
    }

  free (line);
  line = NULL;

  if (ndepends == 0)
    ent->depends = NULL;
  else
    {
      ent->depends =
	(struct prelink_entry **)
	malloc (ndepends * sizeof (struct prelink_entry *));
      if (ent->depends == NULL)
	{
	  error (0, ENOMEM, "%s: Could not record dependencies", ent->filename);
	  goto error_out;
	}
    }

  ent->ndepends = ndepends;
  char *cache_dyn_depends = NULL;
  if (ndepends)
    {
      cache_dyn_depends = alloca (ndepends);
      memset (cache_dyn_depends, '\0', ndepends);
    }
  for (i = 0; i < ndepends; ++i)
    {
      ent->depends[i] = prelink_find_entry (depends [i], NULL, 1);
      if (ent->depends[i] == NULL)
	goto error_out_free_depends;

      if (ent->depends[i]->type == ET_CACHE_DYN)
	{
	  ent->depends[i]->type = ET_NONE;
	  free (ent->depends[i]->depends);
	  ent->depends[i]->depends = NULL;
	  ent->depends[i]->ndepends = 0;
	  cache_dyn_depends[i] = 1;
	}

      if (ent->depends[i]->type != ET_NONE
	  && ent->depends[i]->type != ET_BAD
	  && ent->depends[i]->type != ET_DYN
	  && ent->depends[i]->type != ET_UNPRELINKABLE)
	{
	  error (0, 0, "%s is not a shared library", depends [i]);
error_out_regather_libs:
	  for (i = 0; i < ndepends; ++i)
	    {
	      if (cache_dyn_depends[i] && ent->depends[i]->type == ET_NONE)
		gather_lib (ent->depends[i]);
	    }
	  goto error_out_free_depends;
	}
    }

  free (depends);
  depends = NULL;

  for (i = 0; i < ndepends; ++i)
    if (ent->depends[i]->type == ET_NONE
	&& gather_lib (ent->depends[i]))
      {
	cache_dyn_depends[i] = 0;
	goto error_out_regather_libs;
      }

  for (i = 0; i < ndepends; ++i)
    for (j = 0; j < ent->depends[i]->ndepends; ++j)
      if (ent->depends[i]->depends[j] == ent)
	{
	  error (0, 0, "%s has a dependency cycle", ent->canon_filename);
	  goto error_out_free_depends;
	}

  for (i = 0; i < ndepends; ++i)
    if (ent->depends[i]->type == ET_UNPRELINKABLE)
      {
	error (0, 0, "Could not prelink %s because its dependency %s could not be prelinked",
	       ent->filename, ent->depends[i]->filename);
	ent->type = ET_UNPRELINKABLE;
	goto error_out;
      }

  if (! undo && (!nliblist || liblist) && nliblist == ndepends)
    {
      for (i = 0; i < ndepends; ++i)
	if (liblist[i].l_time_stamp != ent->depends[i]->timestamp
	    || liblist[i].l_checksum != ent->depends[i]->checksum
	    || ! ent->depends[i]->done)
	  break;

      if (i == ndepends)
	ent->done = 2;
    }

  return 0;

error_out_free_depends:
  free (ent->depends);
  ent->depends = NULL;
  ent->ndepends = 0;
error_out:
  if (f)
    execve_close (f);
  free (line);
  free (depends);
  if (dso)
    close_dso (dso);
  return 1;
}

static int
gather_dso (DSO *dso, struct prelink_entry *ent)
{
  int prelinked;

  if (verbose > 5)
    printf ("Checking shared library %s\n", ent->canon_filename);

  if (dso->ehdr.e_type != ET_DYN)
    {
      error (0, 0, "%s is not a shared library", ent->filename);
      close_dso (dso);
      return 1;
    }

  prelinked = (dynamic_info_is_set (dso, DT_GNU_PRELINKED_BIT)
	       && dynamic_info_is_set (dso, DT_CHECKSUM_BIT));
  ent->timestamp = dso->info_DT_GNU_PRELINKED;
  ent->checksum = dso->info_DT_CHECKSUM;
  ent->base = dso->base;
  ent->end = dso->end;
  if (dso->arch->need_rel_to_rela != NULL && ! prelinked)
    {
      /* If the library has not been prelinked yet and we need
	 to convert REL to RELA, then make room for it.  */
      struct reloc_info rinfo;
      GElf_Addr adjust = 0;
      int sec = dso->ehdr.e_shnum;

      if (find_reloc_sections (dso, &rinfo))
	{
	  close_dso (dso);
	  return 1;
	}

      assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
      assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
      if (rinfo.rel_to_rela)
	{
	  sec = rinfo.first;
	  adjust = (dso->shdr[rinfo.last].sh_addr
		    + dso->shdr[rinfo.last].sh_size
		    - dso->shdr[rinfo.first].sh_addr) / 2;
	}
      if (rinfo.rel_to_rela_plt)
	{
	  if (rinfo.plt < sec)
	    sec = rinfo.plt;
	  adjust += dso->shdr[rinfo.plt].sh_size / 2;
	}
      if (adjust)
	{
	  int align = 0, i, last;
	  GElf_Addr start;

	  for (i = rinfo.plt ? rinfo.plt : rinfo.first;
	       i < dso->ehdr.e_shnum; i++)
	    {
	      if (dso->shdr[i].sh_addralign > align)
		align = dso->shdr[i].sh_addralign;
	    }

	  if (rinfo.plt)
	    start = dso->shdr[rinfo.plt].sh_addr
		    + dso->shdr[rinfo.plt].sh_size;
	  else
	    start = dso->shdr[rinfo.first].sh_addr
		    + dso->shdr[rinfo.first].sh_size;

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
		    && (((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz
			  - 1) ^ dso->phdr[i].p_vaddr)
			& ~(dso->arch->max_page_size - 1))
		    && !(((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz
			   + adjust - 1)
			  ^ (dso->phdr[i].p_vaddr + adjust))
			 & ~(dso->arch->max_page_size - 1)))
		  {
		    if (align >= dso->arch->max_page_size)
		      {
			error (0, 0, "%s: Cannot grow reloc sections",
			       ent->filename);
			close_dso (dso);
			return 1;
		      }
		    adjust = (adjust + dso->arch->max_page_size - 1)
			     & ~(dso->arch->max_page_size - 1);
		  }
		last = i;
	      }

	  ent->end += adjust;
	}
    }

  if (gather_deps (dso, ent))
    return 1;

  if (ent->done && ! prelinked && ! undo)
    ent->done = 0;
  ent->type = ET_DYN;
  return 0;
}

static int
gather_lib (struct prelink_entry *ent)
{
  DSO *dso;

  ent->type = ET_BAD;
  dso = open_dso (ent->filename);
  if (dso == NULL)
    return 1;

  return gather_dso (dso, ent);
}

static int
gather_exec (DSO *dso, const struct stat64 *st)
{
  int i, j;
  Elf_Data *data;
  const char *dl;
  struct prelink_entry *ent;

  if (verbose > 5)
    printf ("Checking executable %s\n", dso->filename);

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_INTERP)
      break;

  /* If there are no PT_INTERP segments, it is statically linked.  */
  if (i == dso->ehdr.e_phnum)
    {
make_unprelinkable:
      if (undo)
	goto error_out;

      ent = prelink_find_entry (dso->filename, st, 1);
      if (ent == NULL)
	goto error_out;

      assert (ent->type == ET_NONE);
      ent->type = ET_UNPRELINKABLE;
      if (dso)
	close_dso (dso);
      return 0;
    }

  j = addr_to_sec (dso, dso->phdr[i].p_vaddr);
  if (j == -1 || dso->shdr[j].sh_addr != dso->phdr[i].p_vaddr
      || dso->shdr[j].sh_type != SHT_PROGBITS)
    {
      error (0, 0, "%s: PT_INTERP segment not corresponding to .interp section",
	     dso->filename);
      goto make_unprelinkable;
    }

  data = elf_getdata (dso->scn[j], NULL);
  if (data == NULL)
    {
      error (0, 0, "%s: Could not read .interp section", dso->filename);
      goto error_out;
    }

  i = strnlen (data->d_buf, data->d_size);
  if (i == data->d_size)
    {
      error (0, 0, "%s: .interp section not zero terminated", dso->filename);
      goto error_out;
    }

  dl = dynamic_linker ?: dso->arch->dynamic_linker;
  if (strcmp (dl, data->d_buf) != 0)
    {
      error (0, 0, "%s: Using %s, not %s as dynamic linker", dso->filename,
	     (char *) data->d_buf, dl);
      goto error_out;
    }

  ent = prelink_find_entry (dso->filename, st, 1);
  if (ent == NULL)
    goto error_out;

  assert (ent->type == ET_NONE);
  ent->u.explicit = 1;

  if (gather_deps (dso, ent))
    return 0;

  for (i = 0; i < ent->ndepends; ++i)
    ++ent->depends[i]->refs;

  ent->type = ET_EXEC;
  return 0;

error_out:
  if (dso)
    close_dso (dso);
  return 0;
}

static int
add_dir_to_dirlist (const char *name, dev_t dev, int flags)
{
  const char *canon_name;
  struct prelink_dir *dir;
  size_t len;

  canon_name = prelink_canonicalize (name, NULL);
  if (canon_name == NULL)
    {
      if (! all && implicit)
	return 0;
      error (0, errno, "Could not record directory %s", name);
      return 1;
    }

  len = strlen (canon_name);

  for (dir = blacklist; dir; dir = dir->next)
    if (((dir->flags != FTW_CHDIR && len >= dir->len)
	 || (dir->flags == FTW_CHDIR && len == dir->len))
	&& strncmp (dir->dir, canon_name, dir->len) == 0)
      {
	if (dir->flags == FTW_CHDIR)
	  break;
	if ((dir->flags & FTW_MOUNT) && dir->dev != dev)
	  continue;
	break;
      }

  if (dir != NULL)
    {
      free ((char *) canon_name);
      return 2;
    }

  dir = malloc (sizeof (struct prelink_dir) + len + 1);
  if (dir == NULL)
    {
      error (0, ENOMEM, "Could not record directory %s", name);
      free ((char *) canon_name);
      return 1;
    }

  dir->next = dirs;
  dir->flags = flags;
  dir->dev = dev;
  dir->len = len;
  strcpy (dir->dir, canon_name);
  free ((char *) canon_name);
  dirs = dir;
  return 0;
}

static int
gather_func (const char *name, const struct stat64 *st, int type,
	     struct FTW *ftwp)
{
  unsigned char e_ident [sizeof (Elf64_Ehdr) + sizeof (Elf64_Phdr)];

#ifndef HAVE_FTW_ACTIONRETVAL
  if (blacklist_dir)
    {
      if (strncmp (name, blacklist_dir, blacklist_dir_len) == 0)
	return FTW_CONTINUE;
      free (blacklist_dir);
      blacklist_dir = NULL;
    }
#endif
  if (type == FTW_F && S_ISREG (st->st_mode) && (st->st_mode & 0111))
    {
      int fd, i;
      DSO *dso;
      struct prelink_entry *ent;
      size_t len = strlen (name);
      const char *base = NULL;

      for (i = 0; i < blacklist_next; ++i)
	if (blacklist_ext[i].is_glob)
	  {
	    if (base == NULL)
	      {
		base = strrchr (name, '/');
		if (base == NULL)
		  base = name;
		else
		  ++base;
	      }
	    if (fnmatch (blacklist_ext[i].ext, base, FNM_PERIOD) == 0)
	      return FTW_CONTINUE;
	  }
	else if (blacklist_ext[i].len <= len
		 && memcmp (name + len - blacklist_ext[i].len,
			    blacklist_ext[i].ext, blacklist_ext[i].len) == 0)
	  return FTW_CONTINUE;

      ent = prelink_find_entry (name, st, 0);
      if (ent != NULL && ent->type != ET_NONE)
	{
	  if (verbose > 5)
	    {
	      if (ent->type == ET_CACHE_EXEC || ent->type == ET_CACHE_DYN)
		printf ("Assuming prelinked %s\n", name);
	      if (ent->type == ET_UNPRELINKABLE)
		printf ("Assuming non-prelinkable %s\n", name);
	    }
	  ent->u.explicit = 1;
	  return FTW_CONTINUE;
	}

      if (st->st_size < sizeof (e_ident))
	return FTW_CONTINUE;

      fd = open (name, O_RDONLY);
      if (fd == -1)
	return FTW_CONTINUE;

      if (read (fd, e_ident, sizeof (e_ident)) != sizeof (e_ident))
	{
close_it:
	  close (fd);
	  return FTW_CONTINUE;
	}

      /* Quickly find ET_EXEC ELF binaries and most of PIE binaries.  */

      if (memcmp (e_ident, ELFMAG, SELFMAG) != 0)
	{
make_unprelinkable:
	  if (! undo)
	    {
	      ent = prelink_find_entry (name, st, 1);
	      if (ent != NULL)
		{
		  assert (ent->type == ET_NONE);
		  ent->type = ET_UNPRELINKABLE;
		}
	    }
	  close (fd);
	  return FTW_CONTINUE;
	}

      switch (e_ident [EI_DATA])
	{
	case ELFDATA2LSB:
	  if (e_ident [EI_NIDENT + 1] != 0)
	    goto make_unprelinkable;
	  if (e_ident [EI_NIDENT] != ET_EXEC)
	    {
	      if (e_ident [EI_NIDENT] != ET_DYN)
		goto make_unprelinkable;
	      else if (e_ident [EI_CLASS] == ELFCLASS32)
		{
		  if (e_ident [offsetof (Elf32_Ehdr, e_phoff)]
		      == sizeof (Elf32_Ehdr)
		      && memcmp (e_ident + offsetof (Elf32_Ehdr, e_phoff) + 1,
				 "\0\0\0", 3) == 0
		      && (e_ident [offsetof (Elf32_Ehdr, e_phnum)]
			  || e_ident [offsetof (Elf32_Ehdr, e_phnum) + 1])
		      && e_ident [sizeof (Elf32_Ehdr)
				  + offsetof (Elf32_Phdr, p_type)] == PT_PHDR
		      && memcmp (e_ident + sizeof (Elf32_Ehdr)
				 + offsetof (Elf32_Phdr, p_type) + 1,
				 "\0\0\0", 3) == 0)
		    {
maybe_pie:
		      dso = fdopen_dso (fd, name);
		      if (dso == NULL)
			goto close_it;
		      if (dynamic_info_is_set (dso, DT_DEBUG))
			{
			  close_dso (dso);
			  goto make_unprelinkable;
			}
		      close_dso (dso);
		    }
		  goto close_it;
		}
	      else if (e_ident [EI_CLASS] == ELFCLASS64)
		{
		  if (e_ident [offsetof (Elf64_Ehdr, e_phoff)]
		      == sizeof (Elf64_Ehdr)
		      && memcmp (e_ident + offsetof (Elf64_Ehdr, e_phoff) + 1,
				 "\0\0\0\0\0\0\0", 7) == 0
		      && (e_ident [offsetof (Elf64_Ehdr, e_phnum)]
			  || e_ident [offsetof (Elf64_Ehdr, e_phnum) + 1])
		      && e_ident [sizeof (Elf64_Ehdr)
				  + offsetof (Elf64_Phdr, p_type)] == PT_PHDR
		      && memcmp (e_ident + sizeof (Elf64_Ehdr)
				 + offsetof (Elf64_Phdr, p_type) + 1,
				 "\0\0\0", 3) == 0)
		    goto maybe_pie;
		  goto close_it;
		}
	      else
		goto make_unprelinkable;
	    }
	  break;
	case ELFDATA2MSB:
	  if (e_ident [EI_NIDENT] != 0)
	    goto make_unprelinkable;
	  if (e_ident [EI_NIDENT + 1] != ET_EXEC)
	    {
	      if (e_ident [EI_NIDENT + 1] != ET_DYN)
		goto make_unprelinkable;
	      else if (e_ident [EI_CLASS] == ELFCLASS32)
		{
		  if (e_ident [offsetof (Elf32_Ehdr, e_phoff) + 3]
		      == sizeof (Elf32_Ehdr)
		      && memcmp (e_ident + offsetof (Elf32_Ehdr, e_phoff),
				 "\0\0\0", 3) == 0
		      && (e_ident [offsetof (Elf32_Ehdr, e_phnum)]
			  || e_ident [offsetof (Elf32_Ehdr, e_phnum) + 1])
		      && e_ident [sizeof (Elf32_Ehdr)
				  + offsetof (Elf32_Phdr, p_type) + 3]
			 == PT_PHDR
		      && memcmp (e_ident + sizeof (Elf32_Ehdr)
				 + offsetof (Elf32_Phdr, p_type),
				 "\0\0\0", 3) == 0)
		    goto maybe_pie;
		  goto close_it;
		}
	      else if (e_ident [EI_CLASS] == ELFCLASS64)
		{
		  if (e_ident [offsetof (Elf64_Ehdr, e_phoff) + 7]
		      == sizeof (Elf64_Ehdr)
		      && memcmp (e_ident + offsetof (Elf64_Ehdr, e_phoff),
				 "\0\0\0\0\0\0\0", 7) == 0
		      && (e_ident [offsetof (Elf64_Ehdr, e_phnum)]
			  || e_ident [offsetof (Elf64_Ehdr, e_phnum) + 1])
		      && e_ident [sizeof (Elf64_Ehdr)
				  + offsetof (Elf64_Phdr, p_type) + 3]
			 == PT_PHDR
		      && memcmp (e_ident + sizeof (Elf64_Ehdr)
				 + offsetof (Elf64_Phdr, p_type),
				 "\0\0\0", 3) == 0)
		    goto maybe_pie;
		  goto close_it;
		}
	      else
		goto make_unprelinkable;
	    }
	  break;
	default:
	  goto make_unprelinkable;
	}

      dso = fdopen_dso (fd, name);
      if (dso == NULL)
	return FTW_CONTINUE;

      gather_exec (dso, st);
    }
  else if (type == FTW_D)
    switch (add_dir_to_dirlist (name, st->st_dev, FTW_CHDIR))
      {
      case 0: return FTW_CONTINUE;
      default: return FTW_STOP;
      case 2:
#ifdef HAVE_FTW_ACTIONRETVAL
	return FTW_SKIP_SUBTREE;
#else
	{
	  blacklist_dir_len = strlen (name) + 1;
	  if (blacklist_dir_len > 1 && name[blacklist_dir_len - 2] == '/')
	    blacklist_dir_len--;
	  blacklist_dir = malloc (blacklist_dir_len + 1);
	  if (blacklist_dir == NULL)
	    {
	      error (0, ENOMEM, "Cannot store blacklisted dir name");
	      return FTW_STOP;
	    }
	  memcpy (blacklist_dir, name, blacklist_dir_len - 1);
	  blacklist_dir[blacklist_dir_len - 1] = '/';
	  blacklist_dir[blacklist_dir_len] = '\0';
	  return FTW_CONTINUE;
	}
#endif
      }

  return FTW_CONTINUE;
}

static int
gather_binlib (const char *name, const struct stat64 *st)
{
  unsigned char e_ident [EI_NIDENT + 2];
  int fd, type;
  DSO *dso;
  struct prelink_entry *ent;

  if (! S_ISREG (st->st_mode))
    {
      error (0, 0, "%s is not a regular file", name);
      return 1;
    }

  ent = prelink_find_entry (name, st, 0);
  if (ent != NULL && ent->type == ET_UNPRELINKABLE)
    {
      free (ent->depends);
      ent->depends = NULL;
      ent->ndepends = 0;
      ent->type = ET_NONE;
    }
  if (ent != NULL && ent->type != ET_NONE)
    {
      ent->u.explicit = 1;
      return 0;
    }

  fd = open (name, O_RDONLY);
  if (fd == -1)
    {
      error (0, errno, "Could not open %s", name);
      return 1;
    }

  if (read (fd, e_ident, sizeof (e_ident)) != sizeof (e_ident))
    {
      error (0, errno, "Could not read ELF header from %s", name);
      close (fd);
      return 1;
    }

  /* Quickly find ET_EXEC/ET_DYN ELF binaries/libraries only.  */

  if (memcmp (e_ident, ELFMAG, SELFMAG) != 0)
    {
      error (0, 0, "%s is not an ELF object", name);
      close (fd);
      return 1;
    }

  switch (e_ident [EI_DATA])
    {
    case ELFDATA2LSB:
      if (e_ident [EI_NIDENT + 1] != 0)
	goto unsupported_type;
      type = e_ident [EI_NIDENT];
      break;
    case ELFDATA2MSB:
      if (e_ident [EI_NIDENT] != 0)
	goto unsupported_type;
      type = e_ident [EI_NIDENT + 1];
      break;
    default:
      goto unsupported_type;
    }

  if (type != ET_EXEC && type != ET_DYN)
    {
unsupported_type:
      error (0, 0, "%s is neither ELF executable nor ELF shared library", name);
      close (fd);
      return 1;
    }

  dso = fdopen_dso (fd, name);
  if (dso == NULL)
    return 0;

  if (type == ET_EXEC)
    {
      int i;

      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	if (dso->phdr[i].p_type == PT_INTERP)
	  break;

      /* If there are no PT_INTERP segments, it is statically linked.  */
      if (i == dso->ehdr.e_phnum)
	{
	  error (0, 0, "%s is statically linked", name);
	  close_dso (dso);
	  return 1;
	}

      return gather_exec (dso, st);
    }

  ent = prelink_find_entry (name, st, 1);
  if (ent == NULL)
    {
      close_dso (dso);
      return 1;
    }

  assert (ent->type == ET_NONE);
  ent->type = ET_BAD;
  ent->u.explicit = 1;
  return gather_dso (dso, ent);
}

int
gather_object (const char *name, int deref, int onefs)
{
  struct stat64 st;

  if (stat64 (name, &st) < 0)
    {
      if (implicit)
	return 0;
      error (0, errno, "Could not stat %s", name);
      return 1;
    }

  if (S_ISDIR (st.st_mode))
    {
      int flags = 0, ret;
      if (! deref) flags |= FTW_PHYS;
      if (onefs) flags |= FTW_MOUNT;

      if (implicit && ! deref)
	{
	  ret = add_dir_to_dirlist (name, st.st_dev, flags);
	  if (ret)
	    return ret == 2 ? 0 : 1;
	}
      if (!all && implicit && ! deref)
	return 0;
      ++implicit;
      ret = nftw64 (name, gather_func, 20, flags | FTW_ACTIONRETVAL);
      --implicit;
#ifndef HAVE_FTW_ACTIONRETVAL
      free (blacklist_dir);
      blacklist_dir = NULL;
#endif
      return ret;
    }
  else
    return gather_binlib (name, &st);
}

static struct config_line
{
  struct config_line *next;
  char line[1];
} *config_lines, **config_end = &config_lines;

int
read_config (const char *config)
{
  FILE *file = fopen (config, "r");
  char *line = NULL;
  size_t len, llen;
  int ret = 0;
  struct config_line *c;

  if (file == NULL)
    {
      error (0, errno, "Can't open configuration file %s", config);
      return 1;
    }

  do
    {
      ssize_t i = getline (&line, &len, file);
      char *p;

      if (i < 0)
	break;

      if (line[i - 1] == '\n')
	line[i - 1] = '\0';

      p = strchr (line, '#');
      if (p != NULL)
	*p = '\0';

      p = line + strspn (line, " \t");
      if (p[0] == '-' && p[1] == 'c' && (p[2] == ' ' || p[2] == '\t'))
	{
	  glob_t g;
	  p += 2 + strspn (p + 2, " \t");

	  if (!glob (p, GLOB_BRACE, NULL, &g))
	    {
	      size_t n;

	      for (n = 0; n < g.gl_pathc; ++n)
		if (read_config (g.gl_pathv[n]))
		  {
		    ret = 1;
		    break;
		  }

	      globfree (&g);
	      if (ret)
		break;
	    }
	  continue;
	}

      llen = strlen (p);
      c = malloc (sizeof (*c) + llen);
      if (c == NULL)
	{
	  error (0, ENOMEM, "Could not cache config file");
	  ret = 1;
	  break;
	}

      c->next = NULL;
      memcpy (c->line, p, llen + 1);
      *config_end = c;
      config_end = &c->next;
    }
  while (!feof (file));

  free (line);
  fclose (file);
  return ret;
}

int
gather_config (void)
{
  struct config_line *c;
  int ret = 0;

  implicit = 1;
  for (c = config_lines; c; c = c->next)
    {
      int deref = 0;
      int onefs = 0;
      char *p = c->line;

      while (*p == '-')
	{
	  switch (p[1])
	    {
	    case 'h': deref = 1; break;
	    case 'l': onefs = 1; break;
	    case 'b': p = ""; continue;
	    default:
	      error (0, 0, "Unknown directory option `%s'\n", p);
	      break;
	    }
	  p = p + 2 + strspn (p + 2, " \t");
	}

      if (*p == '\0')
	continue;

      if (strpbrk (p, "*?[{") == NULL)
	{
	  ret = gather_object (p, deref, onefs);
	  if (ret)
	    {
	      ret = 1;
	      break;
	    }
	}
      else
	{
	  glob_t g;

	  if (!glob (p, GLOB_BRACE, NULL, &g))
	    {
	      size_t n;

	      for (n = 0; n < g.gl_pathc; ++n)
		{
		  ret = gather_object (g.gl_pathv[n], deref, onefs);
		  if (ret)
		    {
		      ret = 1;
		      break;
		    }
		}

	      globfree (&g);
	      if (ret)
		break;
	    }
	}
    }

  implicit = 0;
  return ret;
}

static int
gather_check_lib (void **p, void *info)
{
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if (e->type != ET_DYN)
    return 1;

  if (! e->u.explicit)
    {
      struct prelink_dir *dir;
      const char *name;
      size_t len;

      name = strrchr (e->canon_filename, '/');
      if (!name)
	name = e->canon_filename;
      len = name - e->canon_filename;

      for (dir = blacklist; dir; dir = dir->next)
	if (((dir->flags != FTW_CHDIR && len >= dir->len)
	     || (dir->flags == FTW_CHDIR && len == dir->len))
	    && strncmp (dir->dir, e->canon_filename, dir->len) == 0)
	  {
	    if (dir->flags == FTW_CHDIR)
	      break;
	    if ((dir->flags & FTW_MOUNT) && dir->dev != e->dev)
	      continue;
	    break;
	  }

      if (dir != NULL)
	{
	  error (0, 0, "%s is present in a blacklisted directory %s",
		 e->canon_filename, dir->dir);
	  e->type = ET_BAD;
	  return 1;
	}

      for (dir = dirs; dir; dir = dir->next)
	if (((dir->flags != FTW_CHDIR && len >= dir->len)
	     || (dir->flags == FTW_CHDIR && len == dir->len))
	    && strncmp (dir->dir, e->canon_filename, dir->len) == 0)
	  {
	    if (dir->flags == FTW_CHDIR)
	      break;
	    if ((dir->flags & FTW_MOUNT) && dir->dev != e->dev)
	      continue;
	    break;
	  }

      if (dir == NULL)
	{
	  error (0, 0, "%s is not present in any config file directories, nor was specified on command line",
		 e->canon_filename);
	  e->type = ET_BAD;
	  return 1;
	}
    }

  return 1;
}

int
gather_check_libs (void)
{
  struct prelink_dir *dir;
  void *f;

  htab_traverse (prelink_filename_htab, gather_check_lib, NULL);

  dir = dirs;
  while (dir != NULL)
    {
      f = dir;
      dir = dir->next;
      free (f);
    }

  dir = blacklist;
  while (dir != NULL)
    {
      f = dir;
      dir = dir->next;
      free (f);
    }

  dirs = NULL;
  blacklist = NULL;
  return 0;
}

int
add_to_blacklist (const char *name, int deref, int onefs)
{
  const char *canon_name;
  struct prelink_dir *path;
  size_t len;
  struct stat64 st;

  if (stat64 (name, &st) < 0)
    {
      if (implicit)
	return 0;
      error (0, errno, "Could not stat %s", name);
      return 1;
    }

  if (!S_ISDIR (st.st_mode))
    {
      struct prelink_entry *ent;

      ent = prelink_find_entry (name, &st, 1);
      if (ent == NULL)
	return 1;

      ent->type = ET_BAD;
      ent->u.explicit = 1;
      return 0;
    }

  canon_name = prelink_canonicalize (name, NULL);
  if (canon_name == NULL)
    {
      if (implicit)
	return 0;
      error (0, errno, "Could not canonicalize %s", name);
      return 1;
    }

  len = strlen (canon_name);
  path = malloc (sizeof (struct prelink_dir) + len + 1);
  if (path == NULL)
    {
      error (0, ENOMEM, "Could not record path %s", name);
      free ((char *) canon_name);
      return 1;
    }

  path->next = blacklist;
  path->flags = 0;
  if (! deref) path->flags |= FTW_PHYS;
  if (onefs) path->flags |= FTW_MOUNT;
  path->dev = 0;
  path->len = len;
  strcpy (path->dir, canon_name);
  free ((char *) canon_name);
  blacklist = path;
  return 0;
}

void
add_blacklist_ext (const char *ext)
{
  blacklist_ext = realloc (blacklist_ext,
			   (blacklist_next + 1) * sizeof (*blacklist_ext));
  if (blacklist_ext == NULL)
    error (EXIT_FAILURE, errno, "can't create blacklist extension list");
  if (*ext == '*' && strpbrk (ext + 1, "*?[{") == NULL)
    {
      blacklist_ext[blacklist_next].is_glob = 0;
      ext++;
    }
  else
    blacklist_ext[blacklist_next].is_glob = 1;
  blacklist_ext[blacklist_next].ext = strdup (ext);
  if (blacklist_ext[blacklist_next].ext == NULL)
    error (EXIT_FAILURE, errno, "can't create blacklist extension list");
  blacklist_ext[blacklist_next].len = strlen (ext);
  blacklist_next++;
}

int
blacklist_from_config (void)
{
  struct config_line *c;
  int ret = 0;

  implicit = 1;
  for (c = config_lines; c; c = c->next)
    {
      int deref = 0;
      int onefs = 0;
      int blacklist = 0;
      char *p = c->line;

      while (*p == '-')
	{
	  switch (p[1])
	    {
	    case 'h': deref = 1; break;
	    case 'l': onefs = 1; break;
	    case 'b': blacklist = 1; break;
	    }
	  p = p + 2 + strspn (p + 2, " \t");
	}

      if (*p == '\0' || !blacklist)
	continue;

      if (strchr (p, '/') == NULL)
	{
	  add_blacklist_ext (p);
	  continue;
	}

      if (strpbrk (p, "*?[{") == NULL)
	{
	  ret = add_to_blacklist (p, deref, onefs);
	  if (ret)
	    {
	      ret = 1;
	      break;
	    }
	}
      else
	{
	  glob_t g;

	  if (!glob (p, GLOB_BRACE | GLOB_PERIOD, NULL, &g))
	    {
	      size_t n;

	      for (n = 0; n < g.gl_pathc; ++n)
		{
		  ret = add_to_blacklist (g.gl_pathv[n], deref, onefs);
		  if (ret)
		    {
		      ret = 1;
		      break;
		    }
		}

	      globfree (&g);
	      if (ret)
		break;
	    }
	}
    }

  implicit = 0;
  return ret;
}
