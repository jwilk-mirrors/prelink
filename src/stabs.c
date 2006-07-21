/* Copyright (C) 2001, 2005, 2006 Red Hat, Inc.
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
#include <byteswap.h>
#include <endian.h>
#include <error.h>

#include "prelink.h"

#define N_ZERO		0x00
#define N_GSYM		0x20
#define N_FNAME		0x22
#define N_FUN		0x24
#define N_STSYM		0x26
#define N_LCSYM		0x28
#define N_MAIN		0x2a
#define N_BNSYM		0x2e
#define N_PC		0x30
#define N_NSYMS		0x32
#define N_NOMAP		0x34
#define N_OBJ		0x38
#define N_OPT		0x3c
#define N_RSYM		0x40
#define N_M2C		0x42
#define N_SLINE		0x44
#define N_DSLINE	0x46
#define N_BSLINE	0x48
#define N_BROWS		0x48
#define N_DEFD		0x4a
#define N_ENSYM		0x4e
#define N_EHDECL	0x50
#define N_MOD2		0x50
#define N_CATCH		0x54
#define N_SSYM		0x60
#define N_SO		0x64
#define N_LSYM		0x80
#define N_BINCL		0x82
#define N_SOL		0x84
#define N_PSYM		0xa0
#define N_EINCL		0xa2
#define N_ENTRY		0xa4
#define N_LBRAC		0xc0
#define N_EXCL		0xc2
#define N_SCOPE		0xc4
#define N_RBRAC		0xe0
#define N_BCOMM		0xe2
#define N_ECOMM		0xe4
#define N_ECOML		0xe8
#define N_LENG		0xfe

static uint32_t
read_native (char *p)
{
  return *(uint32_t *)p;
}

static uint32_t
read_swap (char *p)
{
  return bswap_32 (*(uint32_t *)p);
}

static void
write_native (char *p, uint32_t v)
{
  *(uint32_t *)p = v;
}

static void
write_swap (char *p, uint32_t v)
{
  *(uint32_t *)p = bswap_32 (v);
}

int
adjust_stabs (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];
  off_t off;
  uint32_t (*read_32) (char *p);
  void (*write_32) (char *p, uint32_t v);
  uint32_t value;
  int sec, type;

  assert (dso->shdr[n].sh_entsize == 12);
  data = elf_getdata (scn, NULL);
  assert (data != NULL && data->d_buf != NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0 && data->d_size == dso->shdr[n].sh_size);
#if __BYTE_ORDER == __BIG_ENDIAN
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
#else
# error Not supported host endianess
#endif
    {
      read_32 = read_native;
      write_32 = write_native;
    }
#if __BYTE_ORDER == __BIG_ENDIAN
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
#endif
    {
      read_32 = read_swap;
      write_32 = write_swap;
    }
  else
    {
      error (0, 0, "%s: Wrong ELF data enconding", dso->filename);
      return 1;
    }

  for (off = 0; off < data->d_size; off += 12)
    {
    switch ((type = *(uint8_t *)(data->d_buf + off + 4)))
      {
      case N_FUN:
	/* If string is "", N_FUN is function length, otherwise
	   it is function start address.  */
	if (read_32 (data->d_buf + off) == 0)
	  break;
	/* FALLTHROUGH */
      case N_STSYM:
      case N_LCSYM:
      case N_CATCH:
      case N_SO:
      case N_SOL:
      case N_BNSYM:
      case N_ENSYM:
	value = read_32 (data->d_buf + off + 8);
	sec = addr_to_sec (dso, value);
	if (sec != -1)
	  {
	    addr_adjust (value, start, adjust);
	    write_32 (data->d_buf + off + 8, value);
	  }
	break;
      /* These should be always 0.  */
      case N_GSYM:
      case N_BINCL:
      case N_EINCL:
      case N_EXCL:
      case N_BCOMM:
      case N_ECOMM:
      /* These contain other values.  */
      case N_ZERO:
      case N_NSYMS:
      case N_NOMAP:
      case N_RSYM:
      case N_LSYM:
      case N_PSYM:
      case N_OPT:
      /* These are relative.  */
      case N_LBRAC:
      case N_RBRAC:
      case N_SLINE:
      case N_BSLINE:
      case N_DSLINE:
	break;
      default:
	error (0, 0, "%s: Unknown stabs code 0x%02x\n", dso->filename, type);
	return 1;
      }
    }

  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  return 0;
}
