/* Generic ELF wrapper for libelf which does not support gelf_ API.
   Copyright (C) 2001 Red Hat, Inc.
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

#ifndef GELFX_H
#define	GELFX_H

#include <libelf.h>
#include <gelf.h>

#ifndef HAVE_GELFX_GETSHDR

#define gelfx_getshdr(elf,scn,shdr) gelf_getshdr(scn,shdr)
#define gelfx_update_shdr(elf,scn,shdr) gelf_update_shdr(scn,shdr)
#define gelfx_getsym(elf,data,ndx,x) gelf_getsym(data,ndx,x)
#define gelfx_update_sym(elf,data,ndx,x) gelf_update_sym(data,ndx,x)
#define gelfx_getdyn(elf,data,ndx,x) gelf_getdyn(data,ndx,x)
#define gelfx_update_dyn(elf,data,ndx,x) gelf_update_dyn(data,ndx,x)
#define gelfx_getrel(elf,data,ndx,x) gelf_getrel(data,ndx,x)
#define gelfx_update_rel(elf,data,ndx,x) gelf_update_rel(data,ndx,x)
#define gelfx_getrela(elf,data,ndx,x) gelf_getrela(data,ndx,x)
#define gelfx_update_rela(elf,data,ndx,x) gelf_update_rela(data,ndx,x)

#endif

#endif	/* GELFX_H */
