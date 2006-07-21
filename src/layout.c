/* Copyright (C) 2001, 2002, 2003, 2004, 2006 Red Hat, Inc.
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
#include <alloca.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "prelinktab.h"
#include "layout.h"

#ifndef NDEBUG
# define DEBUG_LAYOUT
#endif

#ifdef DEBUG_LAYOUT
void
print_ent (struct prelink_entry *e)
{
  printf ("%s: %08x %08x/%08x\n",
	  e->filename, (int)e->base, (int)e->end, (int)e->layend);
}

void
print_list (struct prelink_entry *e)
{
  for (; e; e = e->next)
    print_ent (e);
  printf ("\n");
}
#endif

static int
find_arches (void **p, void *info)
{
  struct layout_libs *l = (struct layout_libs *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;
  int i;

  if (e->type == ET_DYN || e->type == ET_EXEC
      || e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
    {
      for (i = 0; i < l->nbinlibs; ++i)
	if ((l->binlibs[i]->flags & (PCF_ELF64 | PCF_MACHINE))
	    == (e->flags & (PCF_ELF64 | PCF_MACHINE)))
	  return 1;

      l->binlibs[l->nbinlibs++] = e;
    }

  return 1;
}

static int
find_libs (void **p, void *info)
{
  struct layout_libs *l = (struct layout_libs *) info;
  struct prelink_entry *e = * (struct prelink_entry **) p;

  if ((e->flags & (PCF_ELF64 | PCF_MACHINE)) != l->flags)
    return 1;

  if (e->type == ET_DYN || e->type == ET_EXEC
      || e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
    l->binlibs[l->nbinlibs++] = e;
  if (e->type == ET_DYN || e->type == ET_CACHE_DYN)
    l->libs[l->nlibs++] = e;
  if (force)
    e->done = 0;
  if (e->type == ET_CACHE_DYN || e->type == ET_CACHE_EXEC)
    e->done = 2;
  if (e->base & (l->max_page_size - 1))
    {
      e->done = 0;
      e->end -= e->base;
      e->base = 0;
    }

  return 1;
}

static int
refs_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;
  int i;

  /* Dynamic linkers first.  */
  if (! a->ndepends && b->ndepends)
    return -1;
  if (a->ndepends && ! b->ndepends)
    return 1;
  /* Most widely used libraries first.  */
  if (a->refs > b->refs)
    return -1;
  if (a->refs < b->refs)
    return 1;
  /* Largest libraries first.  */
  if (a->layend - a->base > b->layend - b->base)
    return -1;
  if (a->layend - a->base < b->layend - b->base)
    return 1;
  if (a->refs)
    {
      i = strcmp (a->soname, b->soname);
      if (i)
	return i;
    }
  return strcmp (a->filename, b->filename);
}

static int
refs_rnd_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;
  int i, refs;

  /* Dynamic linkers first.  */
  if (! a->ndepends && b->ndepends)
    return -1;
  if (a->ndepends && ! b->ndepends)
    return 1;
  /* Most widely used libraries first with some randomization.  */
  refs = a->refs < b->refs ? a->refs : b->refs;
  if (refs < 8)
    i = 1;
  else if (refs < 32)
    i = 2;
  else if (refs < 128)
    i = 4;
  else
    i = 8;
  if (a->refs > b->refs && a->refs - b->refs >= i)
    return -1;
  if (a->refs < b->refs && b->refs - a->refs >= i)
    return 1;
  if (a->u.tmp < b->u.tmp)
    return -1;
  if (a->u.tmp > b->u.tmp)
    return 1;
  /* Largest libraries first.  */
  if (a->layend - a->base > b->layend - b->base)
    return -1;
  if (a->layend - a->base < b->layend - b->base)
    return 1;
  if (a->refs && b->refs)
    {
      i = strcmp (a->soname, b->soname);
      if (i)
	return i;
    }
  return strcmp (a->filename, b->filename);
}

static int
addr_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;

  if (! a->done)
    return b->done ? 1 : 0;
  else if (! b->done)
    return -1;
  if (a->base < b->base)
    return -1;
  else if (a->base > b->base)
    return 1;
  if (a->layend < b->layend)
    return -1;
  else if (a->layend > b->layend)
    return 1;
  return 0;
}

int deps_cmp (const void *A, const void *B)
{
  struct prelink_entry *a = * (struct prelink_entry **) A;
  struct prelink_entry *b = * (struct prelink_entry **) B;

  if (a->base < b->base)
    return -1;
  if (a->base > b->base)
    return 1;
  return 0;
}

int
layout_libs (void)
{
  struct layout_libs l;
  int arch, *arches, narches;
  struct prelink_entry **plibs, **pbinlibs;

  memset (&l, 0, sizeof (l));
  l.libs = plibs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  l.binlibs = pbinlibs =
    (struct prelink_entry **) alloca (prelink_entry_count
				      * sizeof (struct prelink_entry *));
  htab_traverse (prelink_filename_htab, find_arches, &l);
  narches = l.nbinlibs;
  arches = (int *) alloca (narches * sizeof (int));
  for (arch = 0; arch < narches; ++arch)
    arches[arch] = l.binlibs[arch]->flags & (PCF_ELF64 | PCF_MACHINE);

  for (arch = 0; arch < narches; ++arch)
    {
      struct PLArch *plarch;
      extern struct PLArch __start_pl_arch[], __stop_pl_arch[];
      int i, j, k, m, done, class;
      GElf_Addr mmap_start, mmap_base, mmap_end, mmap_fin, max_page_size;
      GElf_Addr base, size;
      struct prelink_entry *list, *e, *fake, **deps;
      struct prelink_entry fakeent;
      int fakecnt;
      int (*layout_libs_pre) (struct layout_libs *l);
      int (*layout_libs_post) (struct layout_libs *l);

      for (plarch = __start_pl_arch; plarch < __stop_pl_arch; plarch++)
	if (plarch->class == (arches[arch] & PCF_ELF64 ? ELFCLASS64 : ELFCLASS32)
	    && plarch->machine == (arches[arch] & PCF_MACHINE))
	  break;

      if (plarch == __stop_pl_arch)
	error (EXIT_FAILURE, 0, "%d-bit ELF e_machine %04x not supported",
	       (arches[arch] & PCF_ELF64) ? 64 : 32, arches[arch] & PCF_MACHINE);

      list = NULL;
      fake = NULL;
      fakecnt = 0;
      memset (&l, 0, sizeof (l));
      l.flags = arches[arch];
      l.libs = plibs;
      l.binlibs = pbinlibs;
      l.max_page_size = plarch->max_page_size;
      htab_traverse (prelink_filename_htab, find_libs, &l);
      max_page_size = plarch->max_page_size;

      /* Make sure there is some room between libraries.  */
      for (i = 0; i < l.nlibs; ++i)
	l.libs[i]->layend = (l.libs[i]->end + 8192 + max_page_size - 1)
			    & ~(max_page_size - 1);

      if (plarch->layout_libs_init)
	{
	  plarch->layout_libs_init (&l);
	  mmap_base = l.mmap_base;
	  mmap_end = l.mmap_end;
	}
      else
	{
	  mmap_base = plarch->mmap_base;
	  mmap_end = plarch->mmap_end;
	}
      if (mmap_reg_start != ~(GElf_Addr) 0)
	mmap_base = mmap_reg_start;
      if (mmap_reg_end != ~(GElf_Addr) 0)
	mmap_end = mmap_reg_end;
      if (mmap_base >= mmap_end)
	error (EXIT_FAILURE, 0,
	       "--mmap-region-start cannot be bigger than --mmap-region-end");
      class = plarch->class;
      /* The code below relies on having a VA slot as big as <mmap_base,mmap_end)
	 above mmap_end for -R.  */
      if (mmap_end + (mmap_end - mmap_base) <= mmap_end)
	random_base = 0;
      layout_libs_pre = plarch->layout_libs_pre;
      layout_libs_post = plarch->layout_libs_post;

      deps = (struct prelink_entry **)
	     alloca (l.nlibs * sizeof (struct prelink_entry *));

      /* Now see which already prelinked libraries have to be
	 re-prelinked to avoid overlaps.  */
      for (i = 0; i < l.nbinlibs; ++i)
	{
	  for (j = 0, k = 0; j < l.binlibs[i]->ndepends; ++j)
	    if (l.binlibs[i]->depends[j]->type == ET_DYN
		&& l.binlibs[i]->depends[j]->done)
	      deps[k++] = l.binlibs[i]->depends[j];
	  if (k)
	    {
	      qsort (deps, k, sizeof (struct prelink_entry *), deps_cmp);
	      for (j = 1; j < k; ++j)
		if (deps[j]->base < deps[j - 1]->end
		    && (deps[j]->type == ET_DYN
			|| deps[j - 1]->type == ET_DYN))
		  {
		    if (deps[j - 1]->refs < deps[j]->refs)
		      --j;
		    deps[j]->done = 0;
		    --k;
		    memmove (deps + j, deps + j + 1, (k - j) * sizeof (*deps));
		    if (j > 0)
		      --j;
		  }
	    }
	}

      /* If layout_libs_init or the for cycle above cleared
	 done flags for some libraries, make sure all libraries
	 that depend on them are re-prelinked as well.  */
      for (i = 0; i < l.nlibs; ++i)
	if (l.libs[i]->done)
	  for (j = 0; j < l.libs[i]->ndepends; ++j)
	    if (l.libs[i]->depends[j]->done == 0)
	      {
		l.libs[i]->done = 0;
		break;
	      }

      /* Put the already prelinked libs into double linked list.  */
      qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), addr_cmp);
      for (i = 0; i < l.nlibs; ++i)
	if (! l.libs[i]->done || l.libs[i]->layend >= mmap_base)
	  break;
      j = 0;
      if (i < l.nlibs && l.libs[i]->done)
	{
	  if (l.libs[i]->base < mmap_base)
	    random_base = 0;
	  for (j = i + 1; j < l.nlibs; ++j)
	    {
	      if (! l.libs[j]->done || l.libs[j]->base >= mmap_end)
		break;

	      if (l.libs[j]->base < mmap_base || l.libs[j]->layend > mmap_end)
		random_base = 0;
	      l.libs[j]->prev = l.libs[j - 1];
	      l.libs[j - 1]->next = l.libs[j];
	    }
	  list = l.libs[i];
	  list->prev = l.libs[j - 1];
	  while (j < l.nlibs && l.libs[j]->done) ++j;
	}

      mmap_start = mmap_base;
      mmap_fin = mmap_end;
      done = 1;
      if (random_base & 2)
	{
	  mmap_start = seed;
	  if (mmap_start < mmap_base || mmap_start >= mmap_end)
	    mmap_start = mmap_base;

	  mmap_start = (mmap_start + max_page_size - 1) & ~(max_page_size - 1);
	}
      else if (random_base)
	{
	  int fd = open ("/dev/urandom", O_RDONLY);

	  mmap_start = 0;
	  if (fd != -1)
	    {
	      GElf_Addr x;

	      if (read (fd, &x, sizeof (x)) == sizeof (x))
		{
		  mmap_start = x % (mmap_end - mmap_base);
		  mmap_start += mmap_base;
		}

	      close (fd);
	    }

	  if (! mmap_start)
	    {
	      mmap_start = ((mmap_end - mmap_base) >> 16)
			   * (time (NULL) & 0xffff);
	      mmap_start += mmap_base;
	    }

	  seed = mmap_start;
	  mmap_start = (mmap_start + max_page_size - 1) & ~(max_page_size - 1);
	}
      if (random_base)
	{
	  srandom (mmap_start >> 12);
	  for (i = 0; i < l.nlibs; ++i)
	    l.libs[i]->u.tmp = random ();
	  qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), refs_rnd_cmp);
	}
      else
	qsort (l.libs, l.nlibs, sizeof (struct prelink_entry *), refs_cmp);

      if (verbose && l.nlibs > j)
	{
	  printf ("Laying out %d libraries in virtual address space %0*llx-%0*llx\n",
		  l.nlibs - j, class == ELFCLASS32 ? 8 : 16, (long long) mmap_base,
		  class == ELFCLASS32 ? 8 : 16, (long long) mmap_end);
	  if (mmap_start != mmap_base)
	    printf ("Random base 0x%0*llx\n", class == ELFCLASS32 ? 8 : 16,
		    (long long) mmap_start);
	}

      if (layout_libs_pre)
	{
	  l.list = list;
	  l.mmap_base = mmap_base;
	  l.mmap_start = mmap_start;
	  l.mmap_end = mmap_end;
	  layout_libs_pre (&l);
	  list = l.list;
	  mmap_base = l.mmap_base;
	  mmap_start = l.mmap_start;
	  mmap_fin = l.mmap_fin;
	  mmap_end = l.mmap_end;
	  fake = l.fake;
	  fakecnt = l.fakecnt;
	}

      if (mmap_start != mmap_base && list)
	{
	  for (e = list; e != NULL; e = e->next)
	    {
	      if (e->base >= mmap_start)
		break;
	      if (e->layend > mmap_start)
		mmap_start = (e->layend + max_page_size - 1)
			     & ~(max_page_size - 1);
	      e->base += mmap_end - mmap_base;
	      e->end += mmap_end - mmap_base;
	      e->layend += mmap_end - mmap_base;
	      e->done |= 0x80;
	    }

	  if (mmap_start < mmap_end)
	    {
	      if (e && e != list)
		{
		  memset (&fakeent, 0, sizeof (fakeent));
		  fakeent.u.tmp = -1;
		  fakeent.base = mmap_end;
		  fakeent.end = mmap_end;
		  fakeent.layend = mmap_end;
		  fake = &fakeent;
		  fakecnt = 1;
		  fakeent.prev = list->prev;
		  fakeent.next = list;
		  list->prev = fake;
		  fakeent.prev->next = fake;
		  list = e;
		  e->prev->next = NULL;
		}
	    }
	  else
	    {
	      mmap_start = mmap_base;
	      for (e = list; e != NULL; e = e->next)
	      if (e->done & 0x80)
		{
		  e->done &= ~0x80;
		  e->base -= mmap_end - mmap_base;
		  e->end -= mmap_end - mmap_base;
		  e->layend -= mmap_end - mmap_base;
		}
	    }
	}

      if (mmap_start != mmap_base)
	{
	  done |= 0x80;
	  mmap_fin = mmap_end + (mmap_start - mmap_base);
	}

      for (i = 0; i < l.nlibs; ++i)
	l.libs[i]->u.tmp = -1;
      m = -1;

      for (i = 0; i < l.nlibs; ++i)
	if (! l.libs[i]->done)
	  {
	    if (conserve_memory)
	      {
		/* If conserving virtual address space, only consider libraries
		   which ever appear together with this one.  Otherwise consider
		   all libraries.  */
		m = i;
		for (j = 0; j < l.nbinlibs; ++j)
		  {
		    for (k = 0; k < l.binlibs[j]->ndepends; ++k)
		      if (l.binlibs[j]->depends[k] == l.libs[i])
			{
			  for (k = 0; k < l.binlibs[j]->ndepends; ++k)
			    l.binlibs[j]->depends[k]->u.tmp = m;
			  break;
			}
		  }
		for (j = 0; j < fakecnt; ++j)
		  fake[j].u.tmp = m;
	      }

	    size = l.libs[i]->layend - l.libs[i]->base;
	    base = mmap_start;
	    for (e = list; e; e = e->next)
	      if (e->u.tmp == m)
		{
		  if (base + size <= e->base)
		    goto found;

		  if (base < e->layend)
		    base = e->layend;
		}

	    if (base + size > mmap_fin)
	      goto not_found;
found:
	    l.libs[i]->end += base - l.libs[i]->base;
	    l.libs[i]->base = base;
	    l.libs[i]->layend = base + size;
	    if (base >= mmap_end)
	      l.libs[i]->done = done;
	    else
	      l.libs[i]->done = 1;
	    if (list == NULL)
	      {
		list = l.libs[i];
		list->prev = list;
	      }
	    else
	      {
		if (e == NULL)
		  e = list->prev;
		else
		  e = e->prev;
		while (e != list && e->base > base)
		  e = e->prev;
		if (e->base > base)
		  {
		    l.libs[i]->next = list;
		    l.libs[i]->prev = list->prev;
		    list->prev = l.libs[i];
		    list = l.libs[i];
		  }
		else
		  {
		    l.libs[i]->next = e->next;
		    l.libs[i]->prev = e;
		    if (e->next)
		      e->next->prev = l.libs[i];
		    else
		      list->prev = l.libs[i];
		    e->next = l.libs[i];
		  }
	      }
#ifdef DEBUG_LAYOUT
	    {
	      struct prelink_entry *last = list;
	      base = 0;
	      for (e = list; e; last = e, e = e->next)
		{
		  if (e->base < base)
		    abort ();
		  base = e->base;
		  if ((e == list && e->prev->next != NULL)
		      || (e != list && e->prev->next != e))
		    abort ();
		}
	      if (list->prev != last)
		abort ();
	    }
#endif
	    continue;

not_found:
	    error (EXIT_FAILURE, 0, "Could not find virtual address slot for %s",
		   l.libs[i]->filename);
	  }

      if (layout_libs_post)
	{
	  l.list = list;
	  layout_libs_post (&l);
	}

      if (done & 0x80)
	for (e = list; e != NULL; e = e->next)
	  if (e->done & 0x80)
	    {
	      e->done &= ~0x80;
	      e->base -= mmap_end - mmap_base;
	      e->end -= mmap_end - mmap_base;
	      e->layend -= mmap_base - mmap_base;
	    }

      if (verbose)
	{
	  if (narches == 1)
	    printf ("Assigned virtual address space slots for libraries:\n");
	  else
	    printf ("Assigned virtual address space slots for %d-bit %s ELF libraries:\n",
		    class == ELFCLASS32 ? 32 : 64, plarch->name);

	  for (i = 0; i < l.nlibs; ++i)
	    if (l.libs[i]->done >= 1)
	      printf ("%-60s %0*llx-%0*llx\n", l.libs[i]->filename,
		      class == ELFCLASS32 ? 8 : 16, (long long) l.libs[i]->base,
		      class == ELFCLASS32 ? 8 : 16, (long long) l.libs[i]->end);
	}

#ifdef DEBUG_LAYOUT
      for (i = 0; i < l.nbinlibs; ++i)
	{
	  for (j = 0; j < l.binlibs[i]->ndepends; ++j)
	    if ((l.binlibs[i]->depends[j]->type != ET_DYN
		 && l.binlibs[i]->depends[j]->type != ET_CACHE_DYN)
		|| l.binlibs[i]->depends[j]->done == 0)
	      break;
	  if (j < l.binlibs[i]->ndepends)
	    continue;
	  memcpy (deps, l.binlibs[i]->depends,
		  l.binlibs[i]->ndepends * sizeof (struct prelink_entry *));
	  qsort (deps, l.binlibs[i]->ndepends, sizeof (struct prelink_entry *),
		 deps_cmp);
	  for (j = 1; j < l.binlibs[i]->ndepends; ++j)
	    if (deps[j]->base
		< ((deps[j - 1]->end + max_page_size - 1)
		   & ~(max_page_size - 1))
		&& (deps[j]->type == ET_DYN || deps[j - 1]->type == ET_DYN))
	      abort ();
	}
#endif
    }

  return 0;
}
