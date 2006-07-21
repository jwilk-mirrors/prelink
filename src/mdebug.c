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

#include <config.h>
#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <error.h>
#include <stddef.h>

#include "prelink.h"

#define F8(x) unsigned char x[1];
#define F16(x) unsigned char x[2];
#define F24(x) unsigned char x[3];
#define F32(x) unsigned char x[4];
#define F64(x) unsigned char x[8];

typedef struct
{
  F16(magic)
  F16(vstamp)
  F32(ilineMax)
  F32(cbLine)
  F32(cbLineOffset)
  F32(idnMax)
  F32(cbDnOffset)
  F32(ipdMax)
  F32(cbPdOffset)
  F32(isymMax)
  F32(cbSymOffset)
  F32(ioptMax)
  F32(cbOptOffset)
  F32(iauxMax)
  F32(cbAuxOffset)
  F32(issMax)
  F32(cbSsOffset)
  F32(issExtMax)
  F32(cbSsExtOffset)
  F32(ifdMax)
  F32(cbFdOffset)
  F32(crfd)
  F32(cbRfdOffset)
  F32(iextMax)
  F32(cbExtOffset)
} mdebug_hdr_32;

typedef struct
{
  F16(magic)
  F16(vstamp)
  F32(ilineMax)
  F32(idnMax)
  F32(ipdMax)
  F32(isymMax)
  F32(ioptMax)
  F32(iauxMax)
  F32(issMax)
  F32(issExtMax)
  F32(ifdMax)
  F32(crfd)
  F32(iextMax)
  F64(cbLine)
  F64(cbLineOffset)
  F64(cbDnOffset)
  F64(cbPdOffset)
  F64(cbSymOffset)
  F64(cbOptOffset)
  F64(cbAuxOffset)
  F64(cbSsOffset)
  F64(cbSsExtOffset)
  F64(cbFdOffset)
  F64(cbRfdOffset)
  F64(cbExtOffset)
} mdebug_hdr_64;

typedef struct
{
  F32(adr)
  F32(rss)
  F32(issBase)
  F32(cbSs)
  F32(isymBase)
  F32(csym)
  F32(ilineBase)
  F32(cline)
  F32(ioptBase)
  F32(copt)
  F16(ipdFirst)
  F16(cpd)
  F32(iauxBase)
  F32(caux)
  F32(rfdBase)
  F32(crfd)
  F8(bits1)
  F24(bits2)
  F32(cbLineOffset)
  F32(cbLine)
} mdebug_fdr_32;

typedef struct
{
  F64(adr)
  F64(cbLineOffset)
  F64(cbLine)
  F64(cbSs)
  F32(rss)
  F32(issBase)
  F32(isymBase)
  F32(csym)
  F32(ilineBase)
  F32(cline)
  F32(ioptBase)
  F32(copt)
  F32(ipdFirst)
  F32(cpd)
  F32(iauxBase)
  F32(caux)
  F32(rfdBase)
  F32(crfd)
  F8(bits1)
  F24(bits2)
  F32(padding)
} mdebug_fdr_64;

typedef struct
{
  F32(iss)
  F32(value)
  F8(bits1)
  F8(bits2)
  F8(bits3)
  F8(bits4)
} mdebug_sym_32;

typedef struct
{
  F64(value)
  F32(iss)
  F8(bits1)
  F8(bits2)
  F8(bits3)
  F8(bits4)
} mdebug_sym_64;

typedef struct
{
  F8(bits1)
  F8(bits2)
  F16(fd)
  mdebug_sym_32 asym;
} mdebug_ext_32;

typedef struct
{
  mdebug_sym_64 asym;
  F8(bits1)
  F24(bits2)
  F32(fd)
} mdebug_ext_64;

typedef struct
{
  F32(adr)
  F32(isym)
  F32(iline)
  F32(regmask)
  F32(regoffset)
  F32(iopt)
  F32(fregmask)
  F32(fregoffset)
  F32(frameoffset)
  F16(framereg)
  F16(pcreg)
  F32(lnLow)
  F32(lnHigh)
  F32(cbLineOffset)
} mdebug_pdr_32;

typedef struct
{
  F64(adr)
  F64(cbLineOffset)
  F32(isym)
  F32(iline)
  F32(regmask)
  F32(regoffset)
  F32(iopt)
  F32(fregmask)
  F32(fregoffset)
  F32(frameoffset)
  F32(lnLow)
  F32(lnHigh)
  F8(gp_prologue)
  F8(bits1)
  F8(bits2)
  F8(localoff)
  F16(framereg)
  F16(pcreg)
} mdebug_pdr_64;

typedef struct
{
  F32(bits);
} mdebug_rndx;

typedef struct
{
  F8(bits1)
  F8(bits2)
  F8(bits3)
  F8(bits4)
  mdebug_rndx rndx;
  F32(offset)
} mdebug_opt;

typedef struct
{
  F32(rfd)
  F32(index)
} mdebug_dnr;

typedef struct
{
  F32(rfd)
} mdebug_rfd;

#define scNil		0
#define scText		1
#define scData		2
#define scBss		3
#define scRegister	4
#define scAbs		5
#define scUndefined	6
#define scCdbLocal	7
#define scBits		8
#define scCdbSystem	9
#define scDbx		9
#define scRegImage	10
#define scInfo		11
#define scUserStruct	12
#define scSData		13
#define scSBss		14
#define scRData		15
#define scVar		16
#define scCommon	17
#define scSCommon	18
#define scVarRegister	19
#define scVariant	20
#define scSUndefined	21
#define scInit		22
#define scBasedVar	23
#define scXData		24
#define scPData		25
#define scFini		26
#define scRConst	27
#define scMax		32

#define stNil		0
#define stGlobal	1
#define stStatic	2
#define stParam		3
#define stLocal		4
#define stLabel		5
#define stProc		6
#define stBlock		7
#define stEnd		8
#define stMember	9
#define stTypedef	10
#define stFile		11
#define stRegReloc	12
#define stForward	13
#define stStaticProc	14
#define stConstant	15
#define stStaParam	16
#define stStruct	26
#define stUnion		27
#define stEnum		28
#define stIndirect	34
#define stMax		64

struct mdebug
{
  uint32_t (*read_32) (char *);
  GElf_Addr (*read_ptr) (char *);
  void (*write_ptr) (char *, GElf_Addr);
  void (*adjust_sym) (struct mdebug *, unsigned char *, GElf_Addr, GElf_Addr);
  unsigned char *buf;
  DSO *dso;
};

static uint32_t
read_native_32 (char *p)
{
  return *(uint32_t *)p;
}

static uint32_t
read_swap_32 (char *p)
{
  return bswap_32 (*(uint32_t *)p);
}

static GElf_Addr
read_native_ptr32 (char *p)
{
  return *(uint32_t *)p;
}

static GElf_Addr
read_swap_ptr32 (char *p)
{
  return bswap_32 (*(uint32_t *)p);
}

static void
write_native_ptr32 (char *p, GElf_Addr v)
{
  *(uint32_t *)p = v;
}

static void
write_swap_ptr32 (char *p, GElf_Addr v)
{
  *(uint32_t *)p = bswap_32 (v);
}

static GElf_Addr
read_native_ptr64 (char *p)
{
  return *(uint64_t *)p;
}

static GElf_Addr
read_swap_ptr64 (char *p)
{
  return bswap_64 (*(uint64_t *)p);
}

static void
write_native_ptr64 (char *p, GElf_Addr v)
{
  *(uint64_t *)p = v;
}

static void
write_swap_ptr64 (char *p, GElf_Addr v)
{
  *(uint64_t *)p = bswap_64 (v);
}

static inline int
mdebug_sym_relocate (unsigned int st, unsigned int sc)
{
  switch (sc)
    {
    case scData:
    case scBss:
    case scAbs:
    case scSData:
    case scSBss:
    case scRData:
    case scXData:
    case scPData:
      return 1;
    case scText:
    case scInit:
    case scFini:
    case scRConst:
      if (st != stBlock && st != stEnd && st != stFile)
	return 1;
    default:
      return 0;
    }
}

static void
adjust_mdebug_sym_le32 (struct mdebug *mdebug, mdebug_sym_32 *symptr,
			GElf_Addr start, GElf_Addr adjust)
{
  unsigned int st, sc;
  GElf_Addr addr;

  st = symptr->bits1[0] & 0x3f;
  sc = (symptr->bits1[0] >> 6) | ((symptr->bits2[0] & 7) << 2);
  if (mdebug_sym_relocate (st, sc))
    {
      addr = mdebug->read_ptr (symptr->value);
      if (addr >= start && (addr || sc != scAbs))
	mdebug->write_ptr (symptr->value, addr + adjust);
    }
}

static void
adjust_mdebug_sym_be32 (struct mdebug *mdebug, mdebug_sym_32 *symptr,
			GElf_Addr start, GElf_Addr adjust)
{
  unsigned int st, sc;
  GElf_Addr addr;

  st = symptr->bits1[0] >> 2;
  sc = ((symptr->bits1[0] & 3) << 3) | (symptr->bits2[0] >> 5);
  if (mdebug_sym_relocate (st, sc))
    {
      addr = mdebug->read_ptr (symptr->value);
      if (addr >= start && (addr || sc != scAbs))
	mdebug->write_ptr (symptr->value, addr + adjust);
    }
}

static void
adjust_mdebug_sym_le64 (struct mdebug *mdebug, mdebug_sym_64 *symptr,
			GElf_Addr start, GElf_Addr adjust)
{
  unsigned int st, sc;
  GElf_Addr addr;

  st = symptr->bits1[0] & 0x3f;
  sc = (symptr->bits1[0] >> 6) | ((symptr->bits2[0] & 7) << 2);
  if (mdebug_sym_relocate (st, sc))
    {
      addr = mdebug->read_ptr (symptr->value);
      if (addr >= start && (addr || sc != scAbs))
	mdebug->write_ptr (symptr->value, addr + adjust);
    }
}

static void
adjust_mdebug_sym_be64 (struct mdebug *mdebug, mdebug_sym_64 *symptr,
			GElf_Addr start, GElf_Addr adjust)
{
  unsigned int st, sc;
  GElf_Addr addr;

  st = symptr->bits1[0] >> 2;
  sc = ((symptr->bits1[0] & 3) << 3) | (symptr->bits2[0] >> 5);
  if (mdebug_sym_relocate (st, sc))
    {
      addr = mdebug->read_ptr (symptr->value);
      if (addr >= start && (addr || sc != scAbs))
	mdebug->write_ptr (symptr->value, addr + adjust);
    }
}

#define SIZEOf(x) \
  (dso->arch->class == ELFCLASS32 ? sizeof (x##_32) : sizeof (x##_64))
#define SIZEOF(x) SIZEOf(x)
#define OFFSETOf(x,y) \
  (dso->arch->class == ELFCLASS32 ? offsetof (x##_32, y) : offsetof (x##_64, y))
#define OFFSETOF(x,y) OFFSETOf(x,y)

static int
start_mdebug (DSO *dso, int n, struct mdebug *mdebug)
{
  Elf_Data *data = NULL;
  Elf_Scn *scn = dso->scn[n];

  data = elf_getdata (scn, NULL);
  mdebug->buf = data->d_buf;
  mdebug->dso = dso;
  assert (data != NULL && data->d_buf != NULL);
  assert (elf_getdata (scn, data) == NULL);
  assert (data->d_off == 0 && data->d_size == dso->shdr[n].sh_size);
  if (dso->mdebug_orig_offset == 0)
    dso->mdebug_orig_offset = dso->shdr[n].sh_offset;
#if __BYTE_ORDER == __BIG_ENDIAN
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
#else
# error Not supported host endianess
#endif
    {
      mdebug->read_32 = read_native_32;
      if (dso->arch->class == ELFCLASS32)
	{
	  mdebug->read_ptr = read_native_ptr32;
	  mdebug->write_ptr = write_native_ptr32;
	}
      else
	{
	  mdebug->read_ptr = read_native_ptr64;
	  mdebug->write_ptr = write_native_ptr64;
	}
    }
#if __BYTE_ORDER == __BIG_ENDIAN
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
#endif
    {
      mdebug->read_32 = read_swap_32;
      if (dso->arch->class == ELFCLASS32)
	{
	  mdebug->read_ptr = read_swap_ptr32;
	  mdebug->write_ptr = write_swap_ptr32;
	}
      else
	{
	  mdebug->read_ptr = read_swap_ptr64;
	  mdebug->write_ptr = write_swap_ptr64;
	}
    }
  else
    {
      error (0, 0, "%s: Wrong ELF data enconding", dso->filename);
      return 1;
    }
  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
    {
      if (dso->arch->class == ELFCLASS32)
	mdebug->adjust_sym = (void *) adjust_mdebug_sym_le32;
      else
	mdebug->adjust_sym = (void *) adjust_mdebug_sym_le64;
    }
  else
    {
      if (dso->arch->class == ELFCLASS32)
	mdebug->adjust_sym = (void *) adjust_mdebug_sym_be32;
      else
	mdebug->adjust_sym = (void *) adjust_mdebug_sym_be64;
    }

  if (dso->shdr[n].sh_size < SIZEOF (mdebug_hdr))
    {
      error (0, 0, "%s: .mdebug section too small", dso->filename);
      return 1;
    }
  return 0;
}

int
adjust_mdebug (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  struct mdebug mdebug;
  struct { GElf_Off offset; GElf_Off size; size_t entsize; } regions [11];
  int i = 0;
  unsigned char *symptr, *endptr;

  if (start_mdebug (dso, n, &mdebug))
    return 1;

#define READ(x, y, longsize, sz) \
do {									\
  unsigned char *tmp;							\
  tmp = mdebug.buf + OFFSETOF (mdebug_hdr, x);				\
  regions[i].offset = mdebug.read_ptr (tmp);				\
  tmp = mdebug.buf + OFFSETOF (mdebug_hdr, y);				\
  if (longsize)								\
    regions[i].size = mdebug.read_ptr (tmp);				\
  else									\
    regions[i].size = mdebug.read_32 (tmp);				\
  regions[i].entsize = sz;						\
  ++i;									\
} while (0)

  READ (cbLineOffset, cbLine, 1, sizeof (char));
  READ (cbDnOffset, idnMax, 0, sizeof (mdebug_dnr));
  READ (cbPdOffset, ipdMax, 0, SIZEOF (mdebug_pdr));
  READ (cbSymOffset, isymMax, 0, SIZEOF (mdebug_sym));
  READ (cbOptOffset, ioptMax, 0, sizeof (mdebug_opt));
  READ (cbAuxOffset, iauxMax, 0, 4 * sizeof (char));
  READ (cbSsOffset, issMax, 0, sizeof (char));
  READ (cbSsExtOffset, issExtMax, 0, sizeof (char));
  READ (cbFdOffset, ifdMax, 0, SIZEOF (mdebug_fdr));
  READ (cbRfdOffset, crfd, 0, sizeof (mdebug_rfd));
  READ (cbExtOffset, iextMax, 0, SIZEOF (mdebug_ext));

#undef READ

  for (i = 0; i < 11; ++i)
    {
      if (regions[i].offset)
	regions[i].offset -= dso->mdebug_orig_offset;
      regions[i].size *= regions[i].entsize;
      if (regions[i].offset >= dso->shdr[n].sh_size
	  || regions[i].offset + regions[i].size > dso->shdr[n].sh_size)
	{
	  error (0, 0, "%s: File offsets in .mdebug header point outside of .mdebug section",
		 dso->filename);
	  return 1;
	}
    }

  /* Adjust symbols.  */
  if (regions[3].offset)
    for (symptr = mdebug.buf + regions[3].offset,
	 endptr = symptr + regions[3].size;
	 symptr < endptr;
	 symptr += regions[3].entsize)
      mdebug.adjust_sym (&mdebug, symptr, start, adjust);

  /* Adjust file descriptor's addresses.  */
  if (regions[8].offset)
    for (symptr = mdebug.buf + regions[8].offset,
	 endptr = symptr + regions[8].size;
	 symptr < endptr;
	 symptr += regions[8].entsize)
      {
	GElf_Addr addr;

	assert (offsetof (mdebug_fdr_32, adr) == 0);
	assert (offsetof (mdebug_fdr_64, adr) == 0);
	addr = mdebug.read_ptr (symptr);
	if (addr >= start)
	  mdebug.write_ptr (symptr, addr + adjust);
      }

  /* Adjust extended symbols.  */
  if (regions[10].offset)
    for (symptr = mdebug.buf + regions[10].offset
		  + OFFSETOF (mdebug_ext, asym),
	 endptr = symptr + regions[10].size;
	 symptr < endptr;
	 symptr += regions[10].entsize)
      mdebug.adjust_sym (&mdebug, symptr, start, adjust);

  return 0;
}

int
finalize_mdebug (DSO *dso)
{
  int i;
  struct mdebug mdebug;
  GElf_Addr adj;

  for (i = 1; i < dso->ehdr.e_shnum; i++)
    if ((dso->arch->machine == EM_ALPHA
	 && dso->shdr[i].sh_type == SHT_ALPHA_DEBUG)
	|| (dso->arch->machine == EM_MIPS
	    && dso->shdr[i].sh_type == SHT_MIPS_DEBUG))
      break;

  assert (i < dso->ehdr.e_shnum);

  /* If .mdebug's file position did not change, there is nothing to do.  */
  adj = dso->shdr[i].sh_offset - dso->mdebug_orig_offset;
  if (! adj)
    return 0;

  if (start_mdebug (dso, i, &mdebug))
    return 1;

#define ADJUST(x) \
do {									\
  unsigned char *tmp;							\
  GElf_Addr val;							\
  tmp = mdebug.buf + OFFSETOF (mdebug_hdr, x);				\
  val = mdebug.read_ptr (tmp);						\
  if (! val)								\
    break;								\
  val += adj;								\
  if (val < dso->shdr[i].sh_offset					\
      || val >= dso->shdr[i].sh_offset + dso->shdr[i].sh_size)		\
    {									\
      error (0, 0, "%s: File offsets in .mdebug header point outside of .mdebug section", \
	     dso->filename);						\
      return 1;								\
    }									\
  mdebug.write_ptr (tmp, val);						\
} while (0)

  ADJUST (cbLineOffset);
  ADJUST (cbDnOffset);
  ADJUST (cbPdOffset);
  ADJUST (cbSymOffset);
  ADJUST (cbOptOffset);
  ADJUST (cbAuxOffset);
  ADJUST (cbSsOffset);
  ADJUST (cbSsExtOffset);
  ADJUST (cbFdOffset);
  ADJUST (cbRfdOffset);
  ADJUST (cbExtOffset);

#undef ADJUST
  return 0;
}
