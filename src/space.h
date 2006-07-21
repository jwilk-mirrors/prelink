/* Copyright (C) 2001, 2004 Red Hat, Inc.
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

#ifndef SPACE_H
#define SPACE_H

struct readonly_adjust
{
  off_t basemove_adjust;
  GElf_Addr basemove_end;
  int moveend;
  int move2;
  int newcount, *new;
  struct section_move *move;
};

void insert_readonly_section (GElf_Ehdr *ehdr, GElf_Shdr *shdr, int n,
			      struct readonly_adjust *adjust);
int remove_readonly_section (GElf_Ehdr *ehdr, GElf_Shdr *shdr, int n,
			     struct readonly_adjust *adjust);
int find_readonly_space (DSO *dso, GElf_Shdr *add, GElf_Ehdr *ehdr,
			 GElf_Phdr *phdr, GElf_Shdr *shdr,
			 struct readonly_adjust *adjust);

#endif /* SPACE_H */
