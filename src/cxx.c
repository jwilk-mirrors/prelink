/* Copyright (C) 2001, 2002, 2003, 2007, 2009 Red Hat, Inc.
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
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "prelink.h"

static struct
  {
    const char *prefix;
    unsigned char prefix_len, st_info, check_pltref;
  }
specials[] =
  {
    /* G++ 3.0 ABI.  */
    /* Virtual table.  */
    { "_ZTV", 4, GELF_ST_INFO (STB_WEAK, STT_OBJECT), 1 },
    /* Typeinfo.  */
    { "_ZTI", 4, GELF_ST_INFO (STB_WEAK, STT_OBJECT), 0 },
    /* G++ 2.96-RH ABI.  */
    /* Virtual table.  */
    { "__vt_", 5, GELF_ST_INFO (STB_WEAK, STT_OBJECT), 0 },
    { NULL, 0, 0, 0 }
  };

struct find_cxx_sym_valsize
{
  GElf_Addr start;
  GElf_Addr end;
  unsigned int idx;
  unsigned char mark;
};

struct find_cxx_sym_cache
{
  Elf_Data *symtab, *strtab;
  int symsec, strsec, count;
  struct find_cxx_sym_valsize vals[];
};

struct find_cxx_sym
{
  DSO *dso;
  int n;
  struct find_cxx_sym_cache *cache;
  struct prelink_entry *ent;
  Elf_Data *symtab, *strtab;
  int symsec, strsec;
  int lastndx;
  GElf_Sym sym;
};

static int
cachecmp (const void *a, const void *b)
{
  GElf_Addr va = ((const struct find_cxx_sym_valsize *) a)->start;
  GElf_Addr vb = ((const struct find_cxx_sym_valsize *) b)->start;

  if (va < vb)
    return -1;
  if (va > vb)
    return 1;

  va = ((const struct find_cxx_sym_valsize *) a)->end;
  vb = ((const struct find_cxx_sym_valsize *) b)->end;

  if (va < vb)
    return -1;

  return va > vb;
}

static struct find_cxx_sym_cache *
create_cache (DSO *dso, int plt)
{
  Elf_Data *symtab, *strtab;
  Elf_Scn *scn;
  int symsec, strsec, ndx, dndx, maxndx;
  struct find_cxx_sym_cache *cache;
  GElf_Addr top;

  symsec = addr_to_sec (dso, dso->info[DT_SYMTAB]);
  if (symsec == -1)
    return (struct find_cxx_sym_cache *) -1UL;
  scn = dso->scn[symsec];
  symtab = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, symtab) == NULL);
  strsec = addr_to_sec (dso, dso->info[DT_STRTAB]);
  if (strsec == -1)
    return (struct find_cxx_sym_cache *) -1UL;
  scn = dso->scn[strsec];
  strtab = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, strtab) == NULL);
  maxndx = symtab->d_size / dso->shdr[symsec].sh_entsize;

  cache = malloc (sizeof (*cache) + sizeof (cache->vals[0]) * maxndx);
  if (cache == NULL)
    {
      error (0, ENOMEM, "%s: Could load symbol table", dso->filename);
      return NULL;
    }

  cache->symsec = symsec;
  cache->strsec = strsec;
  cache->symtab = symtab;
  cache->strtab = strtab;
  for (ndx = 0, dndx = 0; ndx < maxndx; ++ndx)
    {
      GElf_Sym sym;
      const char *name;
      int k;

      gelfx_getsym (dso->elf, symtab, ndx, &sym);
      if (plt)
	{
	  if (sym.st_shndx != SHN_UNDEF || sym.st_value == 0)
	    continue;
	}
      else if (sym.st_shndx == SHN_UNDEF)
	continue;
      cache->vals[dndx].start = sym.st_value;
      cache->vals[dndx].end = sym.st_value + sym.st_size;
      cache->vals[dndx].idx = ndx;
      cache->vals[dndx].mark = 0;
      name = (const char *) strtab->d_buf + sym.st_name;
      if (!plt && ELF32_ST_VISIBILITY (sym.st_other) == STV_DEFAULT)
	for (k = 0; specials[k].prefix; ++k)
	  if (sym.st_info == specials[k].st_info
	      && strncmp (name, specials[k].prefix,
			  specials[k].prefix_len) == 0)
	    {
	      cache->vals[dndx].mark = 1;
	      break;
	    }
      ++dndx;
    }

  maxndx = dndx;
  qsort (cache->vals, maxndx, sizeof (cache->vals[0]), cachecmp);

  if (!plt)
    {
      for (top = 0, ndx = 0; ndx < maxndx; ++ndx)
	{
	  if (cache->vals[ndx].start < top
	      || (ndx < maxndx - 1
		  && cache->vals[ndx].end > cache->vals[ndx + 1].start))
	    cache->vals[ndx].mark = 0;
	  if (cache->vals[ndx].end > top)
	    top = cache->vals[ndx].end;
	}

      for (ndx = dndx = 0; ndx < maxndx; ++ndx)
	if (cache->vals[ndx].mark)
	  cache->vals[dndx++] = cache->vals[ndx];
    }
  cache->count = dndx;
  return cache;
}

static int
find_cxx_sym (struct prelink_info *info, GElf_Addr addr,
	      struct find_cxx_sym *fcs, int reloc_size,
	      struct find_cxx_sym_cache **cache)
{
  int n, ndeps = info->ent->ndepends + 1;
  unsigned int hi, lo, mid;
  DSO *dso = NULL;
  struct find_cxx_sym_cache *c;

  if (fcs->dso == NULL
      || addr < fcs->dso->base
      || addr >= fcs->dso->end)
    {
      for (n = 1; n < ndeps; ++n)
	{
	  dso = info->dsos[n];
	  if (addr >= dso->base
	      && addr < dso->end)
	    break;
	}

      if (n == ndeps
	  && addr >= info->dso->base
	  && addr < info->dso->end)
	{
	  n = 0;
	  dso = info->dso;
	}

      assert (n < ndeps);

      if (cache[n] == NULL)
	{
	  cache[n] = create_cache (dso, 0);
	  if (cache[n] == NULL)
	    return -2;
	}
      if (cache[n] == (struct find_cxx_sym_cache *) -1UL)
	return -1;

      fcs->n = n;
      fcs->ent = n ? info->ent->depends[n - 1] : info->ent;
      fcs->dso = dso;
      fcs->cache = cache[n];
      fcs->symsec = fcs->cache->symsec;
      fcs->symtab = fcs->cache->symtab;
      fcs->strsec = fcs->cache->strsec;
      fcs->strtab = fcs->cache->strtab;
      fcs->lastndx = -1;
    }
  else
    dso = fcs->dso;

  c = fcs->cache;
  lo = 0;
  hi = c->count;
  if (fcs->lastndx != -1)
    {
      if (c->vals[fcs->lastndx].start <= addr)
	{
	  lo = fcs->lastndx;
	  if (hi - lo >= 16)
	    {
	      if (c->vals[lo + 2].start > addr)
		hi = lo + 2;
	      else if (c->vals[lo + 15].start > addr)
		hi = lo + 15;
	    }
	}
      else
	{
	  hi = fcs->lastndx;
	  if (hi >= 15)
	    {
	      if (c->vals[hi - 2].start <= addr)
		lo = hi - 2;
	      else if (c->vals[hi - 15].start <= addr)
		lo = hi - 15;
	    }
	}
    }
  while (lo < hi)
    {
      mid = (lo + hi) / 2;
      if (c->vals[mid].start <= addr)
	{
	  if (c->vals[mid].end >= addr + reloc_size)
	    {
	      gelfx_getsym (dso->elf, fcs->symtab, c->vals[mid].idx,
			    &fcs->sym);
	      fcs->lastndx = mid;
	      return c->vals[mid].idx;
	    }
	  lo = mid + 1;
	}
      else
	hi = mid;
    }

  return -1;
}

/* The idea here is that C++ virtual tables are always emitted
   in .gnu.linkonce.d.* sections as WEAK symbols and they
   need to be the same.
   We check if they are and if yes, remove conflicts against
   virtual tables which will not be used.  */

int
remove_redundant_cxx_conflicts (struct prelink_info *info)
{
  int i, j, k, n, o, state, removed = 0;
  int ndx, sec;
  unsigned int hi, lo, mid;
  int reloc_type, reloc_size;
  struct find_cxx_sym fcs1, fcs2;
  char *mem1, *mem2;
  const char *name = NULL, *secname = NULL;
  GElf_Addr symtab_start;
  GElf_Word symoff;
  Elf_Data *binsymtab = NULL;
  int binsymtabsec;
  struct prelink_conflict *conflict;
  struct find_cxx_sym_cache **cache;
  struct find_cxx_sym_cache *binsymcache = NULL;
  int ret = 0;
  int rtype_class_valid;

  /* Don't bother doing this for non-C++ programs.  */
  for (i = 0; i < info->ent->ndepends; ++i)
    if (strstr (info->ent->depends[i]->canon_filename, "libstdc++"))
      break;
  if (i == info->ent->ndepends)
    return 0;

  binsymtabsec = addr_to_sec (info->dso, info->dso->info[DT_SYMTAB]);
  if (binsymtabsec != -1)
    {
      Elf_Scn *scn = info->dso->scn[binsymtabsec];

      binsymtab = elf_getdata (scn, NULL);
      assert (elf_getdata (scn, binsymtab) == NULL);
    }

  rtype_class_valid = info->dso->arch->rtype_class_valid;

  state = 0;
  memset (&fcs1, 0, sizeof (fcs1));
  memset (&fcs2, 0, sizeof (fcs2));
  cache = alloca (sizeof (struct find_cxx_sym_cache *)
		  * (info->ent->ndepends + 1));
  memset (cache, '\0', sizeof (struct find_cxx_sym_cache *)
		       * (info->ent->ndepends + 1));
  for (i = 0; i < info->conflict_rela_size; ++i)
    {
      size_t cidx;

      reloc_type = GELF_R_TYPE (info->conflict_rela[i].r_info);
      reloc_size = info->dso->arch->reloc_size (reloc_type);

      if (GELF_R_SYM (info->conflict_rela[i].r_info) != 0)
	continue;

      if (state
	  && fcs1.sym.st_value <= info->conflict_rela[i].r_offset
	  && fcs1.sym.st_value + fcs1.sym.st_size
	     >= info->conflict_rela[i].r_offset + reloc_size)
	{
	  if (state == 3)
	    goto remove_noref;
	  if (state == 2)
	    goto check_pltref;
	  continue;
	}

      n = find_cxx_sym (info, info->conflict_rela[i].r_offset,
			&fcs1, reloc_size, cache);

      state = 0;
      if (n == -1)
	continue;
      if (n == -2)
	{
	  ret = 1;
	  goto out_free_cache;
	}
      state = 1;
      sec = addr_to_sec (fcs1.dso, fcs1.sym.st_value);
      if (sec == -1)
	continue;
      secname = strptr (fcs1.dso, fcs1.dso->ehdr.e_shstrndx,
			fcs1.dso->shdr[sec].sh_name);
      if (secname == NULL)
	continue;

      name = (const char *) fcs1.strtab->d_buf + fcs1.sym.st_name;

      for (k = 0; specials[k].prefix; ++k)
	if (ELF32_ST_VISIBILITY (fcs1.sym.st_other) == STV_DEFAULT
	    && fcs1.sym.st_info == specials[k].st_info
	    && strncmp (name, specials[k].prefix, specials[k].prefix_len) == 0)
	  break;

      if (specials[k].prefix == NULL)
	continue;

      if (strcmp (secname, ".data") != 0
	  && strcmp (secname, ".data.rel.ro") != 0
	  && strcmp (secname, ".sdata") != 0)
	continue;

      if (specials[k].check_pltref)
	state = 2;

      symtab_start = fcs1.dso->shdr[fcs1.symsec].sh_addr - fcs1.dso->base;
      symoff = symtab_start + n * fcs1.dso->shdr[fcs1.symsec].sh_entsize;

      cidx = 0;
      if (info->conflicts[fcs1.n].hash != &info->conflicts[fcs1.n].first)
	cidx = symoff % 251;
      for (conflict = info->conflicts[fcs1.n].hash[cidx]; conflict;
	   conflict = conflict->next)
	if (conflict->symoff == symoff
	    && conflict->reloc_class == rtype_class_valid)
	  break;

      if (conflict == NULL)
	goto check_pltref;

      if (conflict->conflict.ent != fcs1.ent
	  || fcs1.dso->base + conflict->conflictval != fcs1.sym.st_value)
	goto check_pltref;

      if (verbose > 4)
	error (0, 0, "Possible C++ conflict removal from unreferenced table at %s:%s+%d",
	       fcs1.dso->filename, name,
	       (int) (info->conflict_rela[i].r_offset - fcs1.sym.st_value));

      /* Limit size slightly.  */
      if (fcs1.sym.st_size > 16384)
	goto check_pltref;

      o = find_cxx_sym (info, conflict->lookup.ent->base + conflict->lookupval,
			&fcs2, fcs1.sym.st_size, cache);

      if (o == -2)
	{
	  ret = 1;
	  goto out_free_cache;
	}

      if (o == -1
	  || fcs1.sym.st_size != fcs2.sym.st_size
	  || fcs1.sym.st_info != fcs2.sym.st_info
	  || ELF32_ST_VISIBILITY (fcs2.sym.st_other) != STV_DEFAULT
	  || strcmp (name, (char *) fcs2.strtab->d_buf + fcs2.sym.st_name) != 0)
	goto check_pltref;

      mem1 = malloc (fcs1.sym.st_size * 2);
      if (mem1 == NULL)
	{
	  error (0, ENOMEM, "%s: Could not compare %s arrays",
		 info->dso->filename, name);
	  ret = 1;
	  goto out_free_cache;
	}

      mem2 = mem1 + fcs1.sym.st_size;

      if (get_relocated_mem (info, fcs1.dso, fcs1.sym.st_value, mem1,
			     fcs1.sym.st_size)
	  || get_relocated_mem (info, fcs2.dso, fcs2.sym.st_value, mem2,
				fcs1.sym.st_size)
	  || memcmp (mem1, mem2, fcs1.sym.st_size) != 0)
	{
	  free (mem1);
	  goto check_pltref;
	}

      free (mem1);

      state = 3;

remove_noref:
      if (verbose > 3)
	error (0, 0, "Removing C++ conflict from unreferenced table at %s:%s+%d",
	       fcs1.dso->filename, name,
	       (int) (info->conflict_rela[i].r_offset - fcs1.sym.st_value));

      info->conflict_rela[i].r_info =
	GELF_R_INFO (1, GELF_R_TYPE (info->conflict_rela[i].r_info));
      ++removed;
      continue;

check_pltref:
      /* If the binary calls directly (or takes its address) one of the
	 methods in a virtual table, but doesn't define it, there is no
	 need to leave conflicts in the virtual table which will only
	 slow down the code (as it has to hop through binary's .plt
	 back to the method).  */
      if (state != 2
	  || info->conflict_rela[i].r_addend < info->dso->base
	  || info->conflict_rela[i].r_addend >= info->dso->end
	  || binsymtab == NULL)
	continue;

      if (binsymcache == NULL)
	{
	  binsymcache = create_cache (info->dso, 1);
	  if (binsymcache == NULL)
	    {
	      ret = 1;
	      goto out_free_cache;
	    }
	}
      if (binsymcache == (struct find_cxx_sym_cache *) -1UL)
	continue;

      lo = 0;
      mid = 0;
      hi = binsymcache->count;
      while (lo < hi)
	{
	  mid = (lo + hi) / 2;
	  if (binsymcache->vals[mid].start < info->conflict_rela[i].r_addend)
	    lo = mid + 1;
	  else if (binsymcache->vals[mid].start
		   > info->conflict_rela[i].r_addend)
	    hi = mid;
	  else
	    break;
	}
      if (lo >= hi)
	continue;

      while (mid > 0 && binsymcache->vals[mid - 1].start
			== info->conflict_rela[i].r_addend)
	--mid;

      while (mid < binsymcache->count
	     && binsymcache->vals[mid].start
		== info->conflict_rela[i].r_addend)
	{
	  GElf_Sym sym;

	  ndx = binsymcache->vals[mid].idx;
	  mid++;
	  gelfx_getsym (info->dso->elf, binsymtab, ndx, &sym);
	  assert (sym.st_value == info->conflict_rela[i].r_addend);
	  if (sym.st_shndx == SHN_UNDEF && sym.st_value)
	    {
	      struct prelink_symbol *s;
	      size_t maxidx, l;

	      if (verbose > 4)
		error (0, 0, "Possible C++ conflict removal due to reference to binary's .plt at %s:%s+%d",
		       fcs1.dso->filename, name,
		       (int) (info->conflict_rela[i].r_offset
			      - fcs1.sym.st_value));

	      for (s = &info->symbols[ndx]; s; s = s->next)
		if (s->reloc_class == RTYPE_CLASS_PLT)
		  break;

	      if (s == NULL)
		break;

	      maxidx = 1;
	      if (info->conflicts[fcs1.n].hash
		  != &info->conflicts[fcs1.n].first)
		{
		  if (info->conflicts[fcs1.n].hash2 == NULL)
		    {
		      info->conflicts[fcs1.n].hash2
			= calloc (sizeof (struct prelink_conflict *), 251);
		      if (info->conflicts[fcs1.n].hash2 != NULL)
			{
			  for (l = 0; l < 251; l++)
			    for (conflict = info->conflicts[fcs1.n].hash[l];
				 conflict; conflict = conflict->next)
			      if (conflict->reloc_class == rtype_class_valid
				  && conflict->conflict.ent)
				{
				  size_t ccidx
				    = (conflict->lookup.ent->base
				       + conflict->lookupval) % 251;
				  conflict->next2
				    = info->conflicts[fcs1.n].hash2[ccidx];
				  info->conflicts[fcs1.n].hash2[ccidx]
				    = conflict;
				}
			}
		    }
		  if (info->conflicts[fcs1.n].hash2 != NULL)
		    {
		      size_t ccidx = info->conflict_rela[i].r_addend % 251;
		      for (conflict = info->conflicts[fcs1.n].hash2[ccidx];
			   conflict; conflict = conflict->next2)
			if (conflict->lookup.ent->base + conflict->lookupval
			    == info->conflict_rela[i].r_addend
			    && (conflict->conflict.ent->base
				+ conflict->conflictval
				== s->u.ent->base + s->value))
			  goto pltref_remove;
		      break;
		    }
		  maxidx = 251;
		}

	      for (l = 0; l < maxidx; l++)
		for (conflict = info->conflicts[fcs1.n].hash[l];
		     conflict; conflict = conflict->next)
		  if (conflict->lookup.ent->base + conflict->lookupval
		      == info->conflict_rela[i].r_addend
		      && conflict->conflict.ent
		      && (conflict->conflict.ent->base
			  + conflict->conflictval == s->u.ent->base + s->value)
		      && conflict->reloc_class == rtype_class_valid)
		    {
pltref_remove:
		      if (verbose > 3)
			error (0, 0, "Removing C++ conflict due to reference to binary's .plt at %s:%s+%d",
			       fcs1.dso->filename, name,
			       (int) (info->conflict_rela[i].r_offset
				      - fcs1.sym.st_value));

		      info->conflict_rela[i].r_info =
			GELF_R_INFO (1, GELF_R_TYPE (info->conflict_rela[i].r_info));
		      ++removed;
		      goto pltref_check_done;
		    }

pltref_check_done:
	      break;
	    }
	}
    }

  if (removed)
    {
      for (i = 0, j = 0; i < info->conflict_rela_size; ++i)
	if (GELF_R_SYM (info->conflict_rela[i].r_info) == 0)
	  {
	    if (i != j)
	      info->conflict_rela[j] = info->conflict_rela[i];
	    ++j;
	  }
      info->conflict_rela_size = j;
    }

out_free_cache:
  for (i = 0; i < info->ent->ndepends + 1; i++)
    if (cache[i] && cache[i] != (struct find_cxx_sym_cache *) -1UL)
      free (cache[i]);
  if (binsymcache && binsymcache != (struct find_cxx_sym_cache *) -1UL)
    free (binsymcache);
  return ret;
}
