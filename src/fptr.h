/* Copyright (C) 2001 Red Hat, Inc.
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

#ifndef FPTR_H
#define FPTR_H

#include "prelink.h"
#include "hashtab.h"

struct opd_ent
{
  GElf_Addr val;
  GElf_Addr gp;
  GElf_Addr opd;
#define OPD_ENT_PLT 1
#define OPD_ENT_NEW 2
};

struct opd_ent_plt
{
  struct opd_ent v;
  struct prelink_entry *lib;
  GElf_Word symoff;
};

struct opd_ref
{
  GElf_Word symoff;
  GElf_Word refcnt;
  struct opd_ent *ent;
};

struct opd_lib
{
  GElf_Addr symtab_start;
  GElf_Addr opd_start;
  GElf_Addr plt_start;
  union
    {
      struct opd_ref *refs;
      struct opd_ref **refp;
    } u;
  htab_t htab;
  int nrefs;
};

int opd_init (struct prelink_info *info);
int opd_add (struct prelink_info *info, GElf_Word r_sym, int reloc_type);
void opd_note_plt (struct prelink_info *info, GElf_Word r_sym, int reloc_type,
		   GElf_Addr r_offset);
GElf_Addr opd_size (struct prelink_info *info, GElf_Word entsize);

#endif /* FPTR_H */
