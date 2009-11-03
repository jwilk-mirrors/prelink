/* Copyright (C) 2002, 2003, 2004, 2009 Red Hat, Inc.
   Written by Jakub Jelinek <jakub@redhat.com>, 2002.

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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>

#include "prelink.h"
#include "layout.h"

struct opd_rec
{
  GElf_Addr fn, toc, chain;
};

struct opd_lib
{
  GElf_Addr start, size;
  GElf_Addr table[1];
};

static int
ppc64_adjust_section (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  if (dso->shdr[n].sh_type == SHT_PROGBITS
      && ! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			   dso->shdr[n].sh_name), ".got"))
    {
      Elf64_Addr data;

      /* .got[0]-0x8000 points to .got, it needs to be adjusted.  */
      data = read_ube64 (dso, dso->shdr[n].sh_addr);
      if (addr_to_sec (dso, data - 0x8000) == n
	  && data - 0x8000 == dso->shdr[n].sh_addr)
	write_be64 (dso, dso->shdr[n].sh_addr, data + adjust);
    }
  return 0;
}

static int
ppc64_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		  GElf_Addr adjust)
{
  if (dyn->d_tag == DT_PPC64_GLINK && dyn->d_un.d_ptr >= start)
    {
      dyn->d_un.d_ptr += adjust;
      return 1;
    }

  return 0;
}

static int
ppc64_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start,
		  GElf_Addr adjust)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start,
		   GElf_Addr adjust)
{
  if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_PPC64_IRELATIVE)
    {
      GElf_Addr val = read_ube64 (dso, rela->r_offset);

      if (val == rela->r_addend && val >= start)
	write_be64 (dso, rela->r_offset, val + adjust);
      if (rela->r_addend >= start)
	rela->r_addend += adjust;
    }
  else if (GELF_R_TYPE (rela->r_info) == R_PPC64_JMP_IREL)
    {
      if (rela->r_addend >= start)
	rela->r_addend += adjust;
    }
  return 0;
}

static int
ppc64_prelink_rel (struct prelink_info *info, GElf_Rel *rel,
		   GElf_Addr reladdr)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
ppc64_fixup_plt (struct prelink_info *info, GElf_Rela *rela, GElf_Addr value)
{
  DSO *dso = info->dso;
  int sec, i;
  size_t n;
  struct opd_rec rec;

  if (value == 0)
    {
      rec.fn = 0;
      rec.toc = 0;
      rec.chain = 0;
    }
  else if ((sec = addr_to_sec (dso, value)) != -1)
    {
      rec.fn = read_ube64 (dso, value);
      rec.toc = read_ube64 (dso, value + 8);
      rec.chain = read_ube64 (dso, value + 16);
    }
  else
    {
      for (i = 0; i < info->ent->ndepends; ++i)
	if (info->ent->depends[i]->opd
	    && info->ent->depends[i]->opd->start <= value
	    && (info->ent->depends[i]->opd->start
		+ info->ent->depends[i]->opd->size) > value)
	break;

      if (i == info->ent->ndepends)
	{
	  error (0, 0, "%s: R_PPC64_JMP_SLOT doesn't resolve to an .opd address",
		 dso->filename);
	  return 1;
	}
      if ((value - info->ent->depends[i]->opd->start) % 8)
	{
	  error (0, 0, "%s: R_PPC64_JMP_SLOT doesn't resolve to valid .opd section location",
		 dso->filename);
	  return 1;
	}
      n = (value - info->ent->depends[i]->opd->start) / 8;
      rec.fn = info->ent->depends[i]->opd->table[n];
      rec.toc = info->ent->depends[i]->opd->table[n + 1];
      rec.chain = info->ent->depends[i]->opd->table[n + 2];
    }
  write_be64 (dso, rela->r_offset, rec.fn);
  write_be64 (dso, rela->r_offset + 8, rec.toc);
  write_be64 (dso, rela->r_offset + 16, rec.chain);
  return 0;
}

static int
ppc64_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		    GElf_Addr relaaddr)
{
  DSO *dso = info->dso;
  GElf_Addr value;

  if (GELF_R_TYPE (rela->r_info) == R_PPC64_NONE
      || GELF_R_TYPE (rela->r_info) == R_PPC64_IRELATIVE
      || GELF_R_TYPE (rela->r_info) == R_PPC64_JMP_IREL)
    return 0;
  else if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE)
    {
      write_be64 (dso, rela->r_offset, rela->r_addend);
      return 0;
    }
  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      write_be64 (dso, rela->r_offset, value);
      break;
    case R_PPC64_DTPREL64:
      write_be64 (dso, rela->r_offset, value - 0x8000);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      write_be32 (dso, rela->r_offset, value);
      break;
    case R_PPC64_JMP_SLOT:
      return ppc64_fixup_plt (info, rela, value);
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      write_be16 (dso, rela->r_offset, value);
      break;
    case R_PPC64_DTPREL16:
    case R_PPC64_DTPREL16_LO:
      write_be16 (dso, rela->r_offset, value - 0x8000);
      break;
    case R_PPC64_ADDR16_HI:
    case R_PPC64_DTPREL16_HA:
      write_be16 (dso, rela->r_offset, value >> 16);
      break;
    case R_PPC64_DTPREL16_HI:
      write_be16 (dso, rela->r_offset, (value - 0x8000) >> 16);
      break;
    case R_PPC64_ADDR16_HA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 16);
      break;
    case R_PPC64_ADDR16_HIGHER:
      write_be16 (dso, rela->r_offset, value >> 32);
      break;
    case R_PPC64_ADDR16_HIGHERA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 32);
      break;
    case R_PPC64_ADDR16_HIGHEST:
      write_be16 (dso, rela->r_offset, value >> 48);
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 48);
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      write_be16 (dso, rela->r_offset,
		  (value & 0xfffc) | read_ube16 (dso, rela->r_offset & 3));
      break;
    case R_PPC64_ADDR24:
      write_be32 (dso, rela->r_offset,
		  (value & 0x03fffffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xfc000003));
      break;
    case R_PPC64_ADDR14:
      write_be32 (dso, rela->r_offset,
		  (value & 0xfffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xffff0003));
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      write_be32 (dso, rela->r_offset,
		  (value & 0xfffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xffdf0003)
		  | ((((GELF_R_TYPE (rela->r_info) == R_PPC64_ADDR14_BRTAKEN)
		       << 21)
		      ^ (value >> 42)) & 0x00200000));
      break;
    case R_PPC64_REL24:
      write_be32 (dso, rela->r_offset,
		  ((value - rela->r_offset) & 0x03fffffc)
		  | (read_ube32 (dso, rela->r_offset) & 0xfc000003));
      break;
    case R_PPC64_REL32:
      write_be32 (dso, rela->r_offset, value - rela->r_offset);
      break;
    case R_PPC64_REL64:
      write_be64 (dso, rela->r_offset, value - rela->r_offset);
      break;
    /* DTPMOD64 and TPREL* is impossible to predict in shared libraries
       unless prelink sets the rules.  */
    case R_PPC64_DTPMOD64:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_PPC64_DTPMOD64 reloc in executable?",
		 dso->filename);
	  return 1;
	}
      break;
    case R_PPC64_TPREL64:
    case R_PPC64_TPREL16:
    case R_PPC64_TPREL16_LO:
    case R_PPC64_TPREL16_HI:
    case R_PPC64_TPREL16_HA:
      if (dso->ehdr.e_type == ET_EXEC && info->resolvetls)
	{
	  value += info->resolvetls->offset - 0x7000;
	  switch (GELF_R_TYPE (rela->r_info))
	    {
	    case R_PPC64_TPREL64:
	      write_be64 (dso, rela->r_offset, value);
	      break;
	    case R_PPC64_TPREL16:
	    case R_PPC64_TPREL16_LO:
	      write_be16 (dso, rela->r_offset, value);
	      break;
	    case R_PPC64_TPREL16_HI:
	      write_be16 (dso, rela->r_offset, value >> 16);
	      break;
	    case R_PPC64_TPREL16_HA:
	      write_be16 (dso, rela->r_offset, (value + 0x8000) >> 16);
	      break;
	    }
	}
      break;
    case R_PPC64_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_PPC64_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown ppc relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
ppc64_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			   char *buf, GElf_Addr dest_addr)
{
  GElf_Rela *ret;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      buf_write_be64 (buf, rela->r_addend);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      buf_write_be32 (buf, rela->r_addend);
      break;
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
      buf_write_be16 (buf, rela->r_addend);
      break;
    case R_PPC64_IRELATIVE:
      if (dest_addr == 0)
	return 5;
      ret = prelink_conflict_add_rela (info);
      if (ret == NULL)
	return 1;
      ret->r_offset = dest_addr;
      ret->r_info = GELF_R_INFO (0, R_PPC64_IRELATIVE);
      ret->r_addend = rela->r_addend;
      break;
    default:
      abort ();
    }
  return 0;
}

static int
ppc64_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", info->dso->filename);
  return 1;
}

static int
ppc64_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  GElf_Addr value;

  value = info->resolve (info, GELF_R_SYM (rela->r_info),
			 GELF_R_TYPE (rela->r_info));
  value += rela->r_addend;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_PPC64_NONE:
      break;
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      buf_write_be64 (buf, value);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      buf_write_be32 (buf, value);
      break;
    case R_PPC64_ADDR16_HA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HI:
      value = value >> 16;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      buf_write_be16 (buf, value);
      break;
    case R_PPC64_ADDR16_HIGHERA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHER:
      buf_write_be16 (buf, value >> 32);
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHEST:
      buf_write_be16 (buf, value >> 48);
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      buf_write_be16 (buf, (value & 0xfffc)
			   | (buf_read_ube16 (buf) & 3));
      break;
    case R_PPC64_ADDR24:
      buf_write_be32 (buf, (value & 0x03fffffc)
			   | (buf_read_ube32 (buf) & 0xfc000003));
      break;
    case R_PPC64_ADDR14:
      buf_write_be32 (buf, (value & 0xfffc)
			   | (buf_read_ube32 (buf) & 0xffff0003));
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      buf_write_be32 (buf, (value & 0xfffc)
			   | (buf_read_ube32 (buf) & 0xffdf0003)
			   | ((((GELF_R_TYPE (rela->r_info)
				 == R_PPC64_ADDR14_BRTAKEN) << 21)
			       ^ (value >> 42)) & 0x00200000));
      break;
    case R_PPC64_REL24:
      buf_write_be32 (buf, ((value - rela->r_offset) & 0x03fffffc)
			   | (buf_read_ube32 (buf) & 0xfc000003));
      break;
    case R_PPC64_REL32:
      buf_write_be32 (buf, value - rela->r_offset);
      break;
    case R_PPC64_REL64:
      buf_write_be64 (buf, value - rela->r_offset);
      break;
    case R_PPC64_RELATIVE:
      error (0, 0, "%s: R_PPC64_RELATIVE in ET_EXEC object?",
	     info->dso->filename);
      return 1;
    default:
      return 1;
    }
  return 0;
}

static int
ppc64_prelink_conflict_rel (DSO *dso, struct prelink_info *info,
			    GElf_Rel *rel, GElf_Addr reladdr)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			     GElf_Rela *rela, GElf_Addr relaaddr)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *ret;
  int r_type;

  if (GELF_R_TYPE (rela->r_info) == R_PPC64_RELATIVE
      || GELF_R_TYPE (rela->r_info) == R_PPC64_NONE)
    /* Fast path: nothing to do.  */
    return 0;
  conflict = prelink_conflict (info, GELF_R_SYM (rela->r_info),
			       GELF_R_TYPE (rela->r_info));
  if (conflict == NULL)
    {
      switch (GELF_R_TYPE (rela->r_info))
	{
	/* Even local DTPMOD and TPREL relocs need conflicts.  */
	case R_PPC64_DTPMOD64:
	case R_PPC64_TPREL64:
	case R_PPC64_TPREL16:
	case R_PPC64_TPREL16_LO:
	case R_PPC64_TPREL16_HI:
	case R_PPC64_TPREL16_HA:
	  if (info->curtls == NULL || info->dso == dso)
	    return 0;
	  break;
	/* Similarly IRELATIVE relocations always need conflicts.  */
	case R_PPC64_IRELATIVE:
	case R_PPC64_JMP_IREL:
	  break;
	default:
	  return 0;
	}
      value = 0;
    }
  else if (info->dso == dso && !conflict->ifunc)
    return 0;
  else
    {
      /* DTPREL wants to see only real conflicts, not lookups
	 with reloc_class RTYPE_CLASS_TLS.  */
      if (conflict->lookup.tls == conflict->conflict.tls
	  && conflict->lookupval == conflict->conflictval)
	switch (GELF_R_TYPE (rela->r_info))
	  {
	  case R_PPC64_DTPREL64:
	  case R_PPC64_DTPREL16:
	  case R_PPC64_DTPREL16_LO:
	  case R_PPC64_DTPREL16_HI:
	  case R_PPC64_DTPREL16_HA:
	    return 0;
	  }

      value = conflict_lookup_value (conflict);
    }
  ret = prelink_conflict_add_rela (info);
  if (ret == NULL)
    return 1;
  ret->r_offset = rela->r_offset;
  value += rela->r_addend;
  r_type = GELF_R_TYPE (rela->r_info);
  switch (r_type)
    {
    case R_PPC64_GLOB_DAT:
      r_type = R_PPC64_ADDR64;
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
      if (conflict != NULL && conflict->ifunc)
	r_type = R_PPC64_IRELATIVE;
      break;
    case R_PPC64_IRELATIVE:
    case R_PPC64_JMP_IREL:
      break;
    case R_PPC64_JMP_SLOT:
      if (conflict != NULL && conflict->ifunc)
	r_type = R_PPC64_JMP_IREL;
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR16_HA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HI:
      value = value >> 16;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
      if (r_type != R_PPC64_UADDR16)
	r_type = R_PPC64_ADDR16;
      value = ((value & 0xffff) ^ 0x8000) - 0x8000;
      break;
    case R_PPC64_ADDR16_HIGHERA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHER:
      r_type = R_PPC64_ADDR16;
      value = (((value >> 32) & 0xffff) ^ 0x8000) - 0x8000;
      break;
    case R_PPC64_ADDR16_HIGHESTA:
      value += 0x8000;
      /* FALLTHROUGH  */
    case R_PPC64_ADDR16_HIGHEST:
      r_type = R_PPC64_ADDR16;
      value = ((Elf64_Sxword) value) >> 48;
      break;
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      r_type = R_PPC64_ADDR16;
      value = ((value & 0xffff) ^ 0x8000) - 0x8000;
      value |= read_ube16 (dso, rela->r_offset) & 3;
      break;
    case R_PPC64_ADDR24:
      r_type = R_PPC64_ADDR32;
      value = (value & 0x03fffffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xfc000003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR14:
      r_type = R_PPC64_ADDR32;
      value = (value & 0xfffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xffff0003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      r_type = R_PPC64_ADDR32;
      value = (value & 0xfffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xffdf0003)
	      | ((((r_type == R_PPC64_ADDR14_BRTAKEN) << 21)
		  ^ (value >> 42)) & 0x00200000);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_REL24:
      r_type = R_PPC64_ADDR32;
      value = ((value - rela->r_offset) & 0x03fffffc)
	      | (read_ube32 (dso, rela->r_offset) & 0xfc000003);
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_REL32:
      r_type = R_PPC64_ADDR32;
      value -= rela->r_offset;
      value = (Elf32_Sword) value;
      break;
    case R_PPC64_REL64:
      r_type = R_PPC64_ADDR64;
      value -= rela->r_offset;
      break;
    case R_PPC64_DTPMOD64:
    case R_PPC64_DTPREL64:
    case R_PPC64_DTPREL16:
    case R_PPC64_DTPREL16_LO:
    case R_PPC64_DTPREL16_HI:
    case R_PPC64_DTPREL16_HA:
    case R_PPC64_TPREL64:
    case R_PPC64_TPREL16:
    case R_PPC64_TPREL16_LO:
    case R_PPC64_TPREL16_HI:
    case R_PPC64_TPREL16_HA:
      if (conflict != NULL
	  && (conflict->reloc_class != RTYPE_CLASS_TLS
	      || conflict->lookup.tls == NULL))
	{
	  error (0, 0, "%s: TLS reloc not resolving to STT_TLS symbol",
		 dso->filename);
	  return 1;
	}
      tls = conflict ? conflict->lookup.tls : info->curtls;
      r_type = R_PPC64_ADDR16;
      switch (GELF_R_TYPE (rela->r_info))
	{
	case R_PPC64_DTPMOD64:
	  r_type = R_PPC64_ADDR64;
	  value = tls->modid;
	  break;
	case R_PPC64_DTPREL64:
	  r_type = R_PPC64_ADDR64;
	  value -= 0x8000;
	  break;
	case R_PPC64_DTPREL16:
	case R_PPC64_DTPREL16_LO:
	  value -= 0x8000;
	  break;
	case R_PPC64_DTPREL16_HI:
	  value = (value - 0x8000) >> 16;
	  break;
	case R_PPC64_DTPREL16_HA:
	  value >>= 16;
	  break;
	case R_PPC64_TPREL64:
	  r_type = R_PPC64_ADDR64;
	  value += tls->offset - 0x7000;
	  break;
	case R_PPC64_TPREL16:
	case R_PPC64_TPREL16_LO:
	  value += tls->offset - 0x7000;
	  break;
	case R_PPC64_TPREL16_HI:
	  value = (value + tls->offset - 0x7000) >> 16;
	  break;
	case R_PPC64_TPREL16_HA:
	  value = (value + tls->offset - 0x7000 + 0x8000) >> 16;
	  break;
	}
      if (r_type == R_PPC64_ADDR16)
	value = ((value & 0xffff) ^ 0x8000) - 0x8000;
      break;
    default:
      error (0, 0, "%s: Unknown PowerPC64 relocation type %d", dso->filename,
	     r_type);
      return 1;
    }
  if (conflict != NULL && conflict->ifunc
      && r_type != R_PPC64_IRELATIVE && r_type != R_PPC64_JMP_IREL)
    {
      error (0, 0, "%s: relocation %d against IFUNC symbol", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  ret->r_info = GELF_R_INFO (0, r_type);
  ret->r_addend = value;
  return 0;
}

static int
ppc64_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  error (0, 0, "%s: PowerPC64 doesn't support REL relocs", dso->filename);
  return 1;
}

static int
ppc64_need_rel_to_rela (DSO *dso, int first, int last)
{
  return 0;
}

static int
ppc64_undo_prelink_rela (DSO *dso, GElf_Rela *rela, GElf_Addr relaaddr)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_PPC64_NONE:
      return 0;
    case R_PPC64_JMP_SLOT:
      /* .plt section will become SHT_NOBITS.  */
      return 0;
    case R_PPC64_JMP_IREL:
      /* .iplt section will become SHT_NOBITS.  */
      return 0;
    case R_PPC64_RELATIVE:
    case R_PPC64_ADDR64:
    case R_PPC64_IRELATIVE:
      write_be64 (dso, rela->r_offset, rela->r_addend);
      break;
    case R_PPC64_GLOB_DAT:
    case R_PPC64_UADDR64:
    case R_PPC64_DTPREL64:
    case R_PPC64_TPREL64:
    case R_PPC64_DTPMOD64:
    case R_PPC64_REL64:
      write_be64 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_ADDR32:
    case R_PPC64_UADDR32:
    case R_PPC64_REL32:
      write_be32 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_ADDR16_HA:
    case R_PPC64_DTPREL16_HA:
    case R_PPC64_TPREL16_HA:
    case R_PPC64_ADDR16_HI:
    case R_PPC64_DTPREL16_HI:
    case R_PPC64_TPREL16_HI:
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
    case R_PPC64_DTPREL16:
    case R_PPC64_TPREL16:
    case R_PPC64_DTPREL16_LO:
    case R_PPC64_TPREL16_LO:
    case R_PPC64_ADDR16_HIGHERA:
    case R_PPC64_ADDR16_HIGHER:
    case R_PPC64_ADDR16_HIGHESTA:
    case R_PPC64_ADDR16_HIGHEST:
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
      write_be16 (dso, rela->r_offset, 0);
      break;
    case R_PPC64_ADDR24:
    case R_PPC64_REL24:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xfc000003);
      break;
    case R_PPC64_ADDR14:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffff0003);
      break;
    case R_PPC64_ADDR14_BRTAKEN:
    case R_PPC64_ADDR14_BRNTAKEN:
      write_be32 (dso, rela->r_offset,
		  read_ube32 (dso, rela->r_offset) & 0xffdf0003);
      break;
    case R_PPC64_COPY:
      if (dso->ehdr.e_type == ET_EXEC)
	/* COPY relocs are handled specially in generic code.  */
	return 0;
      error (0, 0, "%s: R_PPC64_COPY reloc in shared library?", dso->filename);
      return 1;
    default:
      error (0, 0, "%s: Unknown ppc relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
ppc64_reloc_size (int reloc_type)
{
  switch (reloc_type)
    {
    case R_PPC64_ADDR16:
    case R_PPC64_UADDR16:
    case R_PPC64_ADDR16_LO:
    case R_PPC64_ADDR16_HA:
    case R_PPC64_ADDR16_HI:
    case R_PPC64_ADDR16_LO_DS:
    case R_PPC64_ADDR16_DS:
    case R_PPC64_ADDR16_HIGHER:
    case R_PPC64_ADDR16_HIGHERA:
    case R_PPC64_ADDR16_HIGHEST:
    case R_PPC64_ADDR16_HIGHESTA:
    case R_PPC64_DTPREL16:
    case R_PPC64_DTPREL16_LO:
    case R_PPC64_DTPREL16_HI:
    case R_PPC64_DTPREL16_HA:
    case R_PPC64_TPREL16:
    case R_PPC64_TPREL16_LO:
    case R_PPC64_TPREL16_HI:
    case R_PPC64_TPREL16_HA:
      return 2;
    case R_PPC64_GLOB_DAT:
    case R_PPC64_ADDR64:
    case R_PPC64_UADDR64:
    case R_PPC64_REL64:
    case R_PPC64_DTPMOD64:
    case R_PPC64_DTPREL64:
    case R_PPC64_TPREL64:
    case R_PPC64_IRELATIVE:
      return 8;
    default:
      break;
    }
  return 4;
}

static int
ppc64_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_PPC64_COPY: return RTYPE_CLASS_COPY | RTYPE_CLASS_PLT;
    default:
      if (reloc_type >= R_PPC64_DTPMOD64
	  && reloc_type <= R_PPC64_TPREL16_HIGHESTA)
	return RTYPE_CLASS_TLS;
      return RTYPE_CLASS_PLT;
    }
}

static int
ppc64_read_opd (DSO *dso, struct prelink_entry *ent)
{
  int opd;
  GElf_Addr n, s;

  free (ent->opd);
  ent->opd = NULL;
  for (opd = 1; opd < dso->ehdr.e_shnum; ++opd)
    if (dso->shdr[opd].sh_type == SHT_PROGBITS
	&& ! strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			     dso->shdr[opd].sh_name), ".opd"))
      break;
  if (opd == dso->ehdr.e_shnum)
    return 0;
  ent->opd = malloc (sizeof (struct opd_lib) + dso->shdr[opd].sh_size);
  /* The error will happen only when we'll need the opd.  */
  if (ent->opd == NULL)
    return 0;
  s = dso->shdr[opd].sh_addr;
  for (n = 0; n < dso->shdr[opd].sh_size / 8; ++n, s += 8)
    ent->opd->table[n] = read_ube64 (dso, s);
  ent->opd->start = dso->shdr[opd].sh_addr;
  ent->opd->size = dso->shdr[opd].sh_size;
  return 0;
}

static int
ppc64_free_opd (struct prelink_entry *ent)
{
  free (ent->opd);
  ent->opd = NULL;
  return 0;
}

PL_ARCH = {
  .name = "PowerPC",
  .class = ELFCLASS64,
  .machine = EM_PPC64,
  .alternate_machine = { EM_NONE },
  .R_JMP_SLOT = R_PPC64_JMP_SLOT,
  .R_COPY = R_PPC64_COPY,
  .R_RELATIVE = R_PPC64_RELATIVE,
  .rtype_class_valid = RTYPE_CLASS_PLT,
  .dynamic_linker = "/lib64/ld64.so.1",
  .adjust_section = ppc64_adjust_section,
  .adjust_dyn = ppc64_adjust_dyn,
  .adjust_rel = ppc64_adjust_rel,
  .adjust_rela = ppc64_adjust_rela,
  .prelink_rel = ppc64_prelink_rel,
  .prelink_rela = ppc64_prelink_rela,
  .prelink_conflict_rel = ppc64_prelink_conflict_rel,
  .prelink_conflict_rela = ppc64_prelink_conflict_rela,
  .apply_conflict_rela = ppc64_apply_conflict_rela,
  .apply_rel = ppc64_apply_rel,
  .apply_rela = ppc64_apply_rela,
  .rel_to_rela = ppc64_rel_to_rela,
  .need_rel_to_rela = ppc64_need_rel_to_rela,
  .reloc_size = ppc64_reloc_size,
  .reloc_class = ppc64_reloc_class,
  .read_opd = ppc64_read_opd,
  .free_opd = ppc64_free_opd,
  .max_reloc_size = 8,
  .undo_prelink_rela = ppc64_undo_prelink_rela,
  /* Although TASK_UNMAPPED_BASE is 0x8000000000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x8001000000LL,
  .mmap_end =  0x8100000000LL,
  .max_page_size = 0x10000,
  .page_size = 0x1000
};
