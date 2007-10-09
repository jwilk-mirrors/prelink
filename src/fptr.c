/* Copyright (C) 2001, 2002, 2003, 2007 Red Hat, Inc.
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
#include "fptr.h"

struct opd_refent;

struct opd_tabent
{
  struct opd_ent *ent;
  struct opd_refent *ref;
};

struct opd_refent
{
  GElf_Addr val;
  GElf_Addr gp;
  struct opd_refent *first;
  struct opd_tabent *tabent;
  struct opd_refent *next, *nextref;
  GElf_Word refcnt;
};

struct opd_fptr
{
  /* The first 2 fields have to match opd_refent.  */
  GElf_Addr val;
  GElf_Addr gp;
  struct opd_ent *ent;
};

static void
opd_del (void *p)
{
  free (p);
}

static hashval_t
opd_tabent_hash (const void *p)
{
  struct opd_tabent *e = (struct opd_tabent *)p;

  return e->ent->opd;
}

static int
opd_tabent_eq (const void *p, const void *q)
{
  struct opd_tabent *e = (struct opd_tabent *)p;
  struct opd_tabent *f = (struct opd_tabent *)q;

  return e->ent == f->ent;
}

static hashval_t
opd_refent_hash (const void *p)
{
  struct opd_refent *e = (struct opd_refent *)p;

  return e->val ^ (e->val >> 31);
}

static int
opd_refent_eq (const void *p, const void *q)
{
  struct opd_refent *e = (struct opd_refent *)p;
  struct opd_refent *f = (struct opd_refent *)q;

  return e->val == f->val && e->gp == f->gp;
}

static int
opd_gather_refent (void **p, void *info)
{
  struct opd_refent ***ptr = (struct opd_refent ***) info;
  struct opd_refent *r = *(struct opd_refent **) p, *t;

  for (t = r; t; t = t->next)
    {
      *(*ptr)++ = t;
      t->first = r;
    }
  return 1;
}

static int
opd_refent_cmp (const void *A, const void *B)
{
  struct opd_refent *a = * (struct opd_refent **) A;
  struct opd_refent *b = * (struct opd_refent **) B;

  if (a->refcnt > b->refcnt)
    return -1;
  if (a->refcnt < b->refcnt)
    return 1;
  return 0;
}

int
opd_init (struct prelink_info *info)
{
  int i, j, nrefent = 0;
  struct opd_lib *l;
  struct opd_refent refent, *r, **refarr, **a;
  struct opd_tabent tabent, *t;
  void **tabslot;
  htab_t tabent_htab = NULL, refent_htab = NULL;

  l = calloc (sizeof (struct opd_lib), 1);
  if (l == NULL)
    goto error_mem;
  l->nrefs = (info->symtab_end - info->symtab_start) / info->symtab_entsize;
  if (l->nrefs)
    {
      l->u.refp = calloc (l->nrefs, sizeof (struct opd_ref *));
      if (l->u.refp == NULL)
	goto error_mem;
    }
  else
    l->u.refp = NULL;
  tabent_htab = htab_try_create (100, opd_tabent_hash, opd_tabent_eq, opd_del);
  refent_htab = htab_try_create (100, opd_refent_hash, opd_refent_eq, opd_del);
  l->htab = htab_try_create (100, opd_refent_hash, opd_refent_eq, opd_del);
  if (tabent_htab == NULL || refent_htab == NULL || l->htab == NULL)
    goto error_mem;

  for (i = 0; i < info->ent->ndepends; ++i)
    {
      struct prelink_entry *ent;
      struct prelink_conflict *conflict;
      struct opd_lib *ol;
      size_t maxidx = 1;

      ent = info->ent->depends[i];
      ol = ent->opd;
      if (info->conflicts[i + 1].hash != &info->conflicts[i + 1].first)
	maxidx = 251;
      for (j = 0; j < ol->nrefs; ++j)
	{
	  GElf_Addr symoff = ol->u.refs[j].symoff;
	  refent.val = ol->u.refs[j].ent->val;
	  refent.gp = ol->u.refs[j].ent->gp;
	  for (conflict = info->conflicts[i + 1].hash[symoff % maxidx]; conflict;
	       conflict = conflict->next)
	    {
	      if (conflict->symoff == symoff
		  && conflict->reloc_class != RTYPE_CLASS_COPY
		  && conflict->reloc_class != RTYPE_CLASS_TLS)
		break;
	    }

	  if (conflict)
	    {
	      if (refent.val
		  != conflict->conflict.ent->base + conflict->conflictval
		  || refent.gp != conflict->conflict.ent->pltgot)
		{
		  error (0, 0, "%s: OPD value changed during prelinking",
			 info->ent->filename);
		  goto error_out;
		}

	      refent.val = conflict->lookup.ent->base + conflict->lookupval;
	      refent.gp = conflict->lookup.ent->pltgot;
	    }

	  if (ol->u.refs[j].ent->opd & OPD_ENT_PLT)
	    {
	      struct opd_ent_plt *entp
		= (struct opd_ent_plt *) ol->u.refs[j].ent;
	      int k;
	      size_t idx = 0;

	      for (k = 0; k < info->ent->ndepends; ++k)
		if (info->ent->depends[k] == entp->lib)
		  break;

	      assert (k < info->ent->ndepends);

	      if (info->conflicts[k + 1].hash != &info->conflicts[k + 1].first)
		idx = entp->symoff % 251;
	      for (conflict = info->conflicts[k + 1].hash[idx]; conflict;
		   conflict = conflict->next)
		{
		  if (conflict->symoff == entp->symoff
		      && conflict->reloc_class == RTYPE_CLASS_PLT)
		    break;
		}

	      if (conflict)
		{
		  if (ol->u.refs[j].ent->val
		      != conflict->conflict.ent->base + conflict->conflictval
		      || ol->u.refs[j].ent->gp
			 != conflict->conflict.ent->pltgot)
		    {
		      error (0, 0, "%s: OPD value changed during prelinking",
			     info->ent->filename);
		      goto error_out;
		    }

		  /* FPTR originally pointed into .plt, but since they
		     now resolve to different values, this cannot be used.  */
		  if (refent.val
		      != conflict->lookup.ent->base + conflict->lookupval
		      || refent.gp != conflict->lookup.ent->pltgot)
		    continue;
		}
	      else if (refent.val != ol->u.refs[j].ent->val
		       || refent.gp != ol->u.refs[j].ent->gp)
		continue;
	    }

	  tabslot = htab_find_slot (refent_htab, &refent, INSERT);
	  if (tabslot == NULL)
	    goto error_mem;

	  if (*tabslot != NULL)
	    {
	      for (r = (struct opd_refent *) *tabslot; r; r = r->next)
		if (r->tabent->ent == ol->u.refs[j].ent)
		  {
		    r->refcnt += ol->u.refs[j].refcnt;
		    break;
		  }

	      if (r)
		continue;
	    }

	  r = (struct opd_refent *) calloc (sizeof (struct opd_refent), 1);
	  if (r == NULL)
	    goto error_mem;

	  ++nrefent;
	  r->next = (struct opd_refent *) *tabslot;
	  *tabslot = r;
	  r->val = refent.val;
	  r->gp = refent.gp;
	  r->refcnt = ol->u.refs[j].refcnt;

	  tabent.ent = ol->u.refs[j].ent;

	  tabslot = htab_find_slot (tabent_htab, &tabent, INSERT);
	  if (tabslot == NULL)
	    goto error_mem;

	  if (*tabslot != NULL)
	    {
	      t = (struct opd_tabent *) *tabslot;
	      t->ref->nextref = r;
	      r->nextref = t->ref;
	    }
	  else
	    {
	      t = (struct opd_tabent *) calloc (sizeof (struct opd_tabent), 1);
	      if (t == NULL)
		goto error_mem;
	      t->ent = ol->u.refs[j].ent;
	      *tabslot = t;
	      r->nextref = r;
	      t->ref = r;
	    }

	  r->tabent = t;
	}
    }

  refarr = alloca (nrefent * sizeof (struct opd_refent *));
  a = refarr;
  htab_traverse (refent_htab, opd_gather_refent, &a);
  assert (a == refarr + nrefent);
  qsort (refarr, nrefent, sizeof (struct opd_refent *), opd_refent_cmp);
  for (i = 0; i < nrefent; ++i)
    {
      struct opd_fptr *f;

      if (refarr[i]->tabent == NULL)
	continue;

      f = (struct opd_fptr *) calloc (sizeof (struct opd_fptr), 1);
      if (f == NULL)
	goto error_mem;

      f->val = refarr[i]->val;
      f->gp = refarr[i]->gp;
      f->ent = refarr[i]->tabent->ent;
      tabslot = htab_find_slot (l->htab, f, INSERT);
      if (tabslot == NULL)
	goto error_mem;

      *tabslot = f;
      r = refarr[i]->tabent->ref;
      do
	{
	  if (r != refarr[i])
	    r->tabent = NULL;
	  r = r->nextref;
	}
      while (r != refarr[i]->tabent->ref);

      for (r = refarr[i]->first; r; r = r->next)
	r->tabent = NULL;
    }

  htab_delete (tabent_htab);
  htab_delete (refent_htab);
  info->ent->opd = l;
  return 0;

error_mem:
  error (0, ENOMEM, "%s: Could not create OPD table",
	 info->ent->filename);
error_out:
  if (tabent_htab)
    htab_delete (tabent_htab);
  if (refent_htab)
    htab_delete (refent_htab);
  if (l && l->htab)
    htab_delete (l->htab);
  free (l);
  return 1;
}

int
opd_add (struct prelink_info *info, GElf_Word r_sym, int reloc_type)
{
  struct opd_fptr *f, fp;
  void **tabslot;
  struct opd_lib *l = info->ent->opd;

  if (l->u.refp[r_sym] != NULL)
    {
      ++l->u.refp[r_sym]->refcnt;
      return 0;
    }

  if (ELF64_ST_BIND (info->symtab [r_sym].st_info)
      == STB_LOCAL)
    {
      fp.val = info->symtab [r_sym].st_value;
      fp.gp = info->ent->pltgot;
    }
  else
    {
      fp.val = info->resolve (info, r_sym, reloc_type);
      if (info->resolveent == NULL)
	return 0;
      fp.gp = info->resolveent->pltgot;
    }

  l->u.refp[r_sym] = malloc (sizeof (struct opd_ref));
  if (l->u.refp[r_sym] == NULL)
    goto error_mem;
  l->u.refp[r_sym]->symoff = r_sym;
  l->u.refp[r_sym]->refcnt = 1;
  l->u.refp[r_sym]->ent = NULL;

  tabslot = htab_find_slot (l->htab, &fp, INSERT);
  if (tabslot == NULL)
    goto error_mem;

  if (*tabslot == NULL)
    {
      f = calloc (sizeof (struct opd_fptr), 1);
      if (f == NULL)
	goto error_mem;
      f->val = fp.val;
      f->gp = fp.gp;
      *tabslot = f;
    }

  l->u.refp[r_sym]->ent = *tabslot;
  return 0;

error_mem:
  error (0, ENOMEM, "%s: Could not create OPD table",
	 info->ent->filename);
  return 1;
}

void
opd_note_plt (struct prelink_info *info, GElf_Word r_sym, int reloc_type,
	      GElf_Addr r_offset)
{
  struct opd_fptr *f, fp;
  struct opd_lib *l = info->ent->opd;
  struct opd_ent_plt *entp;

  if (ELF64_ST_BIND (info->symtab [r_sym].st_info)
      == STB_LOCAL)
    {
      fp.val = info->symtab [r_sym].st_value;
      fp.gp = info->ent->pltgot;
    }
  else
    {
      fp.val = info->resolve (info, r_sym, reloc_type);
      if (info->resolveent == NULL)
	return;
      fp.gp = info->resolveent->pltgot;
    }

  f = (struct opd_fptr *) htab_find (l->htab, &fp);
  if (f == NULL || f->ent != NULL)
    return;

  entp = calloc (sizeof (struct opd_ent_plt), 1);
  if (entp == NULL)
    return;

  entp->v.val = fp.val;
  entp->v.gp = fp.gp;
  entp->v.opd = (r_offset - l->plt_start) | (OPD_ENT_PLT | OPD_ENT_NEW);
  entp->lib = info->ent;
  entp->symoff = r_sym;
  f->ent = &entp->v;
}

GElf_Addr
opd_size (struct prelink_info *info, GElf_Word entsize)
{
  struct opd_lib *l = info->ent->opd;
  int i;
  GElf_Addr ret = 0;
  struct opd_ent *e;
  struct opd_fptr *f;

  for (i = 0; i < l->nrefs; ++i)
    if ((f = (struct opd_fptr *) l->u.refp[i]->ent)->ent == NULL)
      {
	e = calloc (sizeof (struct opd_ent), 1);
	if (e == NULL)
	  {
	    error (0, ENOMEM, "%s: Could not create OPD table",
		   info->ent->filename);
	    return -1;
	  }

	e->val = f->val;
	e->gp = f->gp;
	e->opd = ret | OPD_ENT_NEW;
	ret += entsize;
      }

  return ret;
}
