/* Copyright (C) 2001, 2002, 2003 Red Hat, Inc.
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
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "prelink.h"

int
prelink_set_checksum (DSO *dso)
{
  extern uint32_t crc32 (uint32_t crc, unsigned char *buf, size_t len);
  uint32_t crc;
  int i, cvt;

  if (set_dynamic (dso, DT_CHECKSUM, 0, 1))
    return 1;

  if (dso->info_DT_GNU_PRELINKED
      && set_dynamic (dso, DT_GNU_PRELINKED, 0, 1))
    return 1;

  /* Ensure any pending .mdebug/.dynsym/.dynstr etc. modifications
     write_dso would do happen before checksumming.  */
  if (prepare_write_dso (dso))
    return 1;

  cvt = ! ((__BYTE_ORDER == __LITTLE_ENDIAN
	    && dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
	   || (__BYTE_ORDER == __BIG_ENDIAN
	       && dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB));
  crc = 0;
  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      if (! (dso->shdr[i].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR)))
	continue;
      if (dso->shdr[i].sh_type != SHT_NOBITS && dso->shdr[i].sh_size)
	{
	  Elf_Scn *scn = dso->scn[i];
	  Elf_Data *d = NULL;

	  /* Cannot use elf_rawdata here, since the image is not written
	     yet.  */
	  while ((d = elf_getdata (scn, d)) != NULL)
	    {
	      if (cvt && d->d_type != ELF_T_BYTE)
		{
		  gelf_xlatetof (dso->elf, d, d,
				 dso->ehdr.e_ident[EI_DATA]);
		  crc = crc32 (crc, d->d_buf, d->d_size);
		  gelf_xlatetom (dso->elf, d, d,
				 dso->ehdr.e_ident[EI_DATA]);
		}
	      else
		crc = crc32 (crc, d->d_buf, d->d_size);
	    }
	}
    }

  if (set_dynamic (dso, DT_CHECKSUM, crc, 1))
    abort ();
  if (dso->info_DT_GNU_PRELINKED
      && set_dynamic (dso, DT_GNU_PRELINKED, dso->info_DT_GNU_PRELINKED, 1))
    abort ();
  dso->info_DT_CHECKSUM = crc;

  return 0;
}
