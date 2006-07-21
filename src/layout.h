/* Copyright (C) 2001, 2004, 2006 Red Hat, Inc.
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

#ifndef LAYOUT_H
#define LAYOUT_H

struct layout_libs
  {
    struct prelink_entry **libs;
    struct prelink_entry **binlibs;
    struct prelink_entry *list;
    struct prelink_entry *fake;
    GElf_Addr mmap_base, mmap_start, mmap_fin, mmap_end, max_page_size;
    void *arch_data;
    int flags;
    int nlibs;
    int nbinlibs;
    int fakecnt;
  };

#endif /* LAYOUT_H */
