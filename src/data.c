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

#include <config.h>
#include "prelink.h"

#define UREAD(le,nn)						\
uint##nn##_t							\
read_u##le##nn (DSO *dso, GElf_Addr addr)			\
{								\
  unsigned char *data = get_data (dso, addr, NULL);		\
								\
  if (data == NULL)						\
    return 0;							\
								\
  return buf_read_u##le##nn (data);				\
}

#define WRITE(le,nn)						\
int								\
write_##le##nn (DSO *dso, GElf_Addr addr, uint##nn##_t val)	\
{								\
  int sec;							\
  unsigned char *data = get_data (dso, addr, &sec);		\
								\
  if (data == NULL)						\
    return -1;							\
								\
  buf_write_##le##nn (data, val);				\
  elf_flagscn (dso->scn[sec], ELF_C_SET, ELF_F_DIRTY);		\
  return 0;							\
}

#define BUFREADUNE(nn)						\
uint##nn##_t							\
buf_read_une##nn (DSO *dso, unsigned char *buf)			\
{								\
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)		\
    return buf_read_ule32 (buf);				\
  else								\
    return buf_read_ube32 (buf);				\
}

#define READUNE(nn)						\
uint##nn##_t							\
read_une##nn (DSO *dso, GElf_Addr addr)				\
{								\
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)		\
    return read_ule##nn (dso, addr);				\
  else								\
    return read_ube##nn (dso, addr);				\
}

#define WRITENE(nn)						\
void								\
write_ne##nn (DSO *dso, GElf_Addr addr, uint##nn##_t val)	\
{								\
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)		\
    write_le##nn (dso, addr, val);				\
  else								\
    write_be##nn (dso, addr, val);				\
}

#define BUFWRITENE(nn)						\
void								\
buf_write_ne##nn (DSO *dso, unsigned char *buf,			\
		  uint##nn##_t val)				\
{								\
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)		\
    buf_write_le##nn (buf, val);				\
  else								\
    buf_write_be##nn (buf, val);				\
}

#define READWRITE(le,nn) UREAD(le,nn) WRITE(le,nn)
#define READWRITESIZE(nn) \
  READWRITE(le,nn) READWRITE(be,nn) \
  BUFREADUNE(nn) READUNE(nn) \
  WRITENE(nn) BUFWRITENE(nn)

unsigned char *
get_data (DSO *dso, GElf_Addr addr, int *secp)
{
  int sec = addr_to_sec (dso, addr);
  Elf_Data *data = NULL;

  if (sec == -1)
    return NULL;

  if (secp)
    *secp = sec;

  addr -= dso->shdr[sec].sh_addr;
  while ((data = elf_getdata (dso->scn[sec], data)) != NULL)
    if (data->d_off <= addr && data->d_off + data->d_size > addr)
      return (unsigned char *) data->d_buf + (addr - data->d_off);

  return NULL;
}

/* Initialize IT so that the first byte it provides is address ADDR
   of DSO.  */

void
init_data_iterator (struct data_iterator *it, DSO *dso, GElf_Addr addr)
{
  it->dso = dso;
  it->data = NULL;
  it->addr = addr;
}

/* Return a pointer to the next SIZE bytes pointed to by IT, and move
   IT to the end of the returned block.  Return null if the data could
   not be read for some reason.  */

unsigned char *
get_data_from_iterator (struct data_iterator *it, GElf_Addr size)
{
  unsigned char *ptr;

  /* If we're at the end of a data block, move onto the next.  */
  if (it->data && it->data->d_off + it->data->d_size == it->sec_offset)
    it->data = elf_getdata (it->dso->scn[it->sec], it->data);

  if (it->data == NULL)
    {
      /* Find out which section contains the next byte.  */
      it->sec = addr_to_sec (it->dso, it->addr);
      if (it->sec < 0)
	return NULL;

      /* Fast-forward to the block that contains ADDR, if any.  */
      it->sec_offset = it->addr - it->dso->shdr[it->sec].sh_addr;
      do
	it->data = elf_getdata (it->dso->scn[it->sec], it->data);
      while (it->data && it->data->d_off + it->data->d_size <= it->sec_offset);
    }

  /* Make sure that all the data we want is included in this block.  */
  if (it->data == NULL
      || it->data->d_off > it->sec_offset
      || it->data->d_off + it->data->d_size < it->sec_offset + size)
    return NULL;

  ptr = (unsigned char *) it->data->d_buf + (it->sec_offset - it->data->d_off);
  it->sec_offset += size;
  it->addr += size;
  return ptr;
}

/* Read the symbol pointed to by IT into SYM and move IT onto the
   next symbol.  Return true on success.  */

int
get_sym_from_iterator (struct data_iterator *it, GElf_Sym *sym)
{
  GElf_Addr offset, size;
  unsigned char *ptr;

  size = gelf_fsize (it->dso->elf, ELF_T_SYM, 1, EV_CURRENT);
  ptr = get_data_from_iterator (it, size);
  if (ptr != NULL)
    {
      offset = ptr - (unsigned char *) it->data->d_buf;
      if (offset % size == 0)
	{
	  gelfx_getsym (it->dso->elf, it->data, offset / size, sym);
	  return 1;
	}
    }
  return 0;
}

inline uint8_t
buf_read_u8 (unsigned char *data)
{
  return *data;
}

inline uint16_t
buf_read_ule16 (unsigned char *data)
{
  return data[0] | (data[1] << 8);
}

inline uint16_t
buf_read_ube16 (unsigned char *data)
{
  return data[1] | (data[0] << 8);
}

inline uint32_t
buf_read_ule32 (unsigned char *data)
{
  return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

inline uint32_t
buf_read_ube32 (unsigned char *data)
{
  return data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
}

inline uint64_t
buf_read_ule64 (unsigned char *data)
{
  return (data[0] | (data[1] << 8) | (data[2] << 16))
	 | (((uint64_t)data[3]) << 24)
	 | (((uint64_t)data[4]) << 32)
	 | (((uint64_t)data[5]) << 40)
	 | (((uint64_t)data[6]) << 48)
	 | (((uint64_t)data[7]) << 56);
}

inline uint64_t
buf_read_ube64 (unsigned char *data)
{
  return (data[7] | (data[6] << 8) | (data[5] << 16))
	 | (((uint64_t)data[4]) << 24)
	 | (((uint64_t)data[3]) << 32)
	 | (((uint64_t)data[2]) << 40)
	 | (((uint64_t)data[1]) << 48)
	 | (((uint64_t)data[0]) << 56);
}

inline void
buf_write_8 (unsigned char *data, uint8_t val)
{
  *data = val;
}

inline void
buf_write_le16 (unsigned char *data, uint16_t val)
{
  data[0] = val;
  data[1] = val >> 8;
}

inline void
buf_write_be16 (unsigned char *data, uint16_t val)
{
  data[1] = val;
  data[0] = val >> 8;
}

inline void
buf_write_le32 (unsigned char *data, uint32_t val)
{
  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
}

inline void
buf_write_be32 (unsigned char *data, uint32_t val)
{
  data[3] = val;
  data[2] = val >> 8;
  data[1] = val >> 16;
  data[0] = val >> 24;
}

inline void
buf_write_le64 (unsigned char *data, uint64_t val)
{
  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
  data[4] = val >> 32;
  data[5] = val >> 40;
  data[6] = val >> 48;
  data[7] = val >> 56;
}

inline void
buf_write_be64 (unsigned char *data, uint64_t val)
{
  data[7] = val;
  data[6] = val >> 8;
  data[5] = val >> 16;
  data[4] = val >> 24;
  data[3] = val >> 32;
  data[2] = val >> 40;
  data[1] = val >> 48;
  data[0] = val >> 56;
}

READWRITE(,8)
READWRITESIZE(16)
READWRITESIZE(32)
READWRITESIZE(64)

const char *
strptr (DSO *dso, int sec, off_t offset)
{
  Elf_Scn *scn;
  Elf_Data *data;

  scn = dso->scn[sec];
  if (offset >= 0 && offset < dso->shdr[sec].sh_size)
    {
      data = NULL;
      while ((data = elf_getdata (scn, data)) != NULL)
	{
	  if (data->d_buf
	      && offset >= data->d_off
	      && offset < data->d_off + data->d_size)
	    return (const char *) data->d_buf + (offset - data->d_off);
	}
    }

  return NULL;
}
