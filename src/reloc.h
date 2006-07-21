/* Copyright (C) 2001, 2002 Red Hat, Inc.
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

#ifndef RELOC_H
#define RELOC_H

#include "prelink.h"

struct reloc_info
{
  int first; /* First dynamic SHT_REL* section.  */
  int last; /* Last dynamic SHT_REL* section not counting .rel*.plt.  */
  int plt; /* .rel*.plt section.  */
  int overlap; /* 1 if DT_REL{,A}SZ range includes DT_PLTRELSZ range.  */
  int reldyn_rela; /* first..last sections were originally RELA.  */
  int plt_rela; /* plt section was originally RELA.  */
  int rel_to_rela; /* first..last sections have to be converted REL->RELA.  */
  int rel_to_rela_plt; /* plt section has to be converted REL->RELA.  */
  int relcount; /* DT_RELCOUNT resp. DT_RELACOUNT.  */
};

int find_reloc_sections (DSO *dso, struct reloc_info *rinfo);
int convert_rel_to_rela (DSO *dso, int i);
int convert_rela_to_rel (DSO *dso, int i);
int update_dynamic_rel (DSO *dso, struct reloc_info *rinfo);
int undo_sections (DSO *dso, int undo, struct section_move *move,
		   struct reloc_info *rinfo, GElf_Ehdr *ehdr,
		   GElf_Phdr *phdr, GElf_Shdr *shdr);

#endif /* RELOC_H */
