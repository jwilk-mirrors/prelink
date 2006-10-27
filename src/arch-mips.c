/* Copyright (C) 2006 CodeSourcery
   Written by Richard Sandiford <richard@codesourcery.com>, 2006

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

/* GENERAL NOTES

   The psABI defines R_MIPS_REL32 as A - EA + S, where the value of EA
   depends on the symbol index.  If the index is less than DT_MIPS_GOTSYM,
   EA is the symbol's st_value "plus displacement".  If the index is greater
   than or equal to DT_MIPS_GOTSYM, EA is the original value of the
   associated GOT entry.

   However, glibc's dynamic linker implements a different definition.
   If the index is less than DT_MIPS_GOTSYM, the dynamic linker adds the
   symbol's st_value and the base address to the addend.  If the index
   is greater than or equal to DT_MIPS_GOTSYM, the dynamic linker adds
   the final symbol value to the addend.

   MIPS GOTs are divided into three parts:

     - Reserved entries (of which GNU objects have 2)
     - Local entries
     - Global entries

   DT_MIPS_LOCAL_GOTNO gives the total number of reserved and local
   entries.  The local entries all hold virtual addresses and the
   dynamic linker will add the base address to each one.

   Unlike most other architectures, the MIPS ABI does not use
   relocations to initialize the global GOT entries.  Instead, global
   GOT entry X is mapped to dynamic symbol DT_MIPS_GOTSYM + X, and there
   are a total of DT_MIPS_SYMTABNO - DT_MIPS_GOTSYM global GOT entries.

   The interpretation of a global GOT entry depends on the symbol entry
   and the initial GOT contents.  The psABI lists the following cases:

      st_shndx    st_type     st_value      initial GOT value
      --------    -------     --------      -----------------
   A: SHN_UNDEF   STT_FUNC    0             st_value (== 0) / QS
   B: SHN_UNDEF   STT_FUNC    stub address  st_value / QS
   C: SHN_UNDEF   all others  0             st_value (== 0) / QS
   D: SHN_COMMON  any         alignment     0 / QS
   E: all others  STT_FUNC    value         st_value / stub address
   F: all others  all others  value         st_value

   (wording slightly modified from the psABI table).  Here, QS denotes
   Quickstart values.

   The dynamic linker treats each case as follows:

   - [A, B when not binding lazily, C, D, E when not binding lazily, F]
     Resolve the symbol and store its value in the GOT.

   - [B when binding lazily] Set the GOT entry to the st_value plus
     the base address.

   - [E when binding lazily] If the GOT entry is different from the st_value,
     add the base addreess to the GOT entry.  Otherwise resolve the symbol
     and store its value in the GOT (as for A, C, etc).

   As the table shows, we can install Quickstart values for types A-D.
   Installing Quickstart values for type F should be a no-op, because the
   GOT should already hold the desired value.  Installing Quickstart values
   for type E would either be a no-op (if the GOT entry already contains
   st_value) or would lose the address of the lazy binding stub.  */

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

/* The thread pointer points 0x7000 past the first static TLS block.  */
#define TLS_TP_OFFSET 0x7000

/* Dynamic thread vector pointers point 0x8000 past the start of each
   TLS block.  */
#define TLS_DTV_OFFSET 0x8000

/* The number of reserved entries at the beginning of the GOT.
   The dynamic linker points entry 0 to the resolver function
   and entry 1 to the link_map.  */
#define RESERVED_GOTNO 2

/* A structure for iterating over local GOT entries.  */
struct mips_local_got_iterator {
  /* The DSO containing the GOT.  */
  DSO *dso;

  /* The size of a GOT entry.  */
  GElf_Word entry_size;

  /* The index of the current GOT entry.  */
  GElf_Word got_index;

  /* A pointer to the current GOT entry.  */
  unsigned char *got_entry;

  /* True if we failed to read an entry correctly.  */
  int failed;

  /* Used internally to obtain GOT_ENTRY.  */
  struct data_iterator got_iterator;
};

/* Set up LGI to iterate over DSO's local GOT.  The caller should use
   mips_get_local_got_entry to read the first entry.  */

static inline void
mips_init_local_got_iterator (struct mips_local_got_iterator *lgi, DSO *dso)
{
  lgi->dso = dso;
  lgi->entry_size = gelf_fsize (dso->elf, ELF_T_WORD, 1, EV_CURRENT);
  lgi->got_index = RESERVED_GOTNO - 1;
  lgi->failed = 0;
  init_data_iterator (&lgi->got_iterator, dso,
		      dso->info[DT_PLTGOT]
		      + (lgi->got_index + 1) * lgi->entry_size);
}

/* Return true if LGI has not reached the end of the GOT and if the next
   entry can be accessed.  When returning true, use LGI's fields to
   describe the next entry.  */

static inline int
mips_get_local_got_entry (struct mips_local_got_iterator *lgi)
{
  lgi->got_index++;
  if (lgi->got_index >= lgi->dso->info_DT_MIPS_LOCAL_GOTNO)
    return 0;

  lgi->got_entry = get_data_from_iterator (&lgi->got_iterator,
					   lgi->entry_size);
  if (lgi->got_entry == NULL)
    {
      error (0, 0, "%s: Malformed local GOT\n", lgi->dso->filename);
      lgi->failed = 1;
      return 0;
    }

  return 1;
}

/* A structure for iterating over global GOT entries.  */
struct mips_global_got_iterator {
  /* The DSO containing the GOT.  */
  DSO *dso;

  /* The size of a GOT entry.  */
  GElf_Word entry_size;

  /* The virtual address of the current GOT entry.  */
  GElf_Addr got_addr;

  /* The index of the associated entry in the dynamic symbol table.  */
  GElf_Word sym_index;

  /* A pointer to the current GOT entry.  */
  unsigned char *got_entry;

  /* The symbol associated with the current GOT entry.  */
  GElf_Sym sym;

  /* True if we failed to read an entry correctly.  */
  int failed;

  /* Used internally to obtain GOT_ENTRY and SYM.  */
  struct data_iterator got_iterator;
  struct data_iterator sym_iterator;
};

/* Set up GGI to iterate over DSO's global GOT.  The caller should use
   mips_get_global_got_entry to read the first entry.  */

static inline void
mips_init_global_got_iterator (struct mips_global_got_iterator *ggi, DSO *dso)
{
  GElf_Word sym_size;

  ggi->dso = dso;
  ggi->entry_size = gelf_fsize (dso->elf, ELF_T_WORD, 1, EV_CURRENT);
  ggi->got_addr = (dso->info[DT_PLTGOT]
		   + (dso->info_DT_MIPS_LOCAL_GOTNO - 1) * ggi->entry_size);
  ggi->sym_index = dso->info_DT_MIPS_GOTSYM - 1;
  ggi->failed = 0;

  sym_size = gelf_fsize (dso->elf, ELF_T_SYM, 1, EV_CURRENT);
  init_data_iterator (&ggi->got_iterator, dso,
		      ggi->got_addr + ggi->entry_size);
  init_data_iterator (&ggi->sym_iterator, dso,
		      dso->info[DT_SYMTAB] + (ggi->sym_index + 1) * sym_size);
}

/* Return true if GGI has not reached the end of the GOT and if the next
   entry can be accessed.  When returning true, use GGI's fields to
   describe the next entry.  */

static inline int
mips_get_global_got_entry (struct mips_global_got_iterator *ggi)
{
  ggi->sym_index++;
  ggi->got_addr += ggi->entry_size;
  if (ggi->sym_index >= ggi->dso->info_DT_MIPS_SYMTABNO)
    return 0;

  ggi->got_entry = get_data_from_iterator (&ggi->got_iterator,
					   ggi->entry_size);
  if (ggi->got_entry == NULL
      || !get_sym_from_iterator (&ggi->sym_iterator, &ggi->sym))
    {
      error (0, 0, "%s: Malformed global GOT\n", ggi->dso->filename);
      ggi->failed = 1;
      return 0;
    }

  return 1;
}

static int
mips_arch_adjust (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  struct mips_local_got_iterator lgi;
  struct mips_global_got_iterator ggi;
  GElf_Addr value;

  if (dso->info[DT_PLTGOT] == 0)
    return 0;

  /* Adjust every local GOT entry by ADJUST.  Every adjustment moves
     the code and data, so we do not need to check START here.  */
  mips_init_local_got_iterator (&lgi, dso);
  while (mips_get_local_got_entry (&lgi))
    {
      value = buf_read_une32 (dso, lgi.got_entry);
      buf_write_ne32 (dso, lgi.got_entry, value + adjust);
    }

  /* Adjust every global GOT entry.  Referring to the table above:

     For [A, B, C]: Adjust the GOT entry if it contains st_value
     and if the symbol's value will be adjusted.

     For [D]: Do nothing.  SHN_COMMON entries never need adjusting.

     For [E, F]: Adjust the GOT entry if it does not contain st_value
     -- in other words, if it is a type E entry that points to a lazy
     binding stub -- or if the symbol's value will also be adjusted.  */
  mips_init_global_got_iterator (&ggi, dso);
  while (mips_get_global_got_entry (&ggi))
    {
      value = buf_read_une32 (dso, ggi.got_entry);
      if (ggi.sym.st_shndx != SHN_COMMON
	  && value >= start
	  && (value == ggi.sym.st_value
	      ? adjust_symbol_p (dso, &ggi.sym)
	      : ggi.sym.st_shndx != SHN_UNDEF))
	buf_write_ne32 (dso, ggi.got_entry, value + adjust);
    }

  return lgi.failed || ggi.failed;
}

static int
mips_adjust_dyn (DSO *dso, int n, GElf_Dyn *dyn, GElf_Addr start,
		 GElf_Addr adjust)
{
  switch (dyn->d_tag)
    {
    case DT_MIPS_TIME_STAMP:
    case DT_MIPS_ICHECKSUM:
    case DT_MIPS_IVERSION:
    case DT_MIPS_CONFLICT:
    case DT_MIPS_CONFLICTNO:
    case DT_MIPS_LIBLIST:
    case DT_MIPS_LIBLISTNO:
      error (0, 0, "%s: File contains QuickStart information", dso->filename);
      return 1;

    case DT_MIPS_BASE_ADDRESS:
    case DT_MIPS_RLD_MAP:
    case DT_MIPS_OPTIONS:
      if (dyn->d_un.d_ptr >= start)
	dyn->d_un.d_ptr += adjust;
      return 1;

    case DT_MIPS_LOCAL_GOTNO:
    case DT_MIPS_UNREFEXTNO:
    case DT_MIPS_SYMTABNO:
    case DT_MIPS_HIPAGENO:
    case DT_MIPS_GOTSYM:
      /* We don't change the layout of the GOT or symbol table.  */
      return 1;

    case DT_MIPS_RLD_VERSION:
    case DT_MIPS_FLAGS:
      /* We don't change these properties.  */
      return 1;
    }
  return 0;
}

/* Read the addend for a relocation in DSO.  If RELA is nonnull,
   use its r_addend, otherwise read a 32-bit in-place addend from
   address R_OFFSET.  */

static inline uint32_t
mips_read_addend (DSO *dso, GElf_Addr r_offset, GElf_Rela *rela)
{
  return rela ? rela->r_addend : read_une32 (dso, r_offset);
}

/* Like mips_read_addend, but change the addend to VALUE.  */

static inline void
mips_write_addend (DSO *dso, GElf_Addr r_offset, GElf_Rela *rela,
		   uint32_t value)
{
  if (rela)
    rela->r_addend = (int32_t) value;
  else
    write_ne32 (dso, r_offset, value);
}

/* There is a relocation of type R_INFO against address R_OFFSET in DSO.
   Adjust it so that virtual addresses >= START are increased by ADJUST
   If the relocation is in a RELA section, RELA points to the relocation,
   otherwise it is null.  */

static int
mips_adjust_reloc (DSO *dso, GElf_Addr r_offset, GElf_Xword r_info,
		   GElf_Addr start, GElf_Addr adjust, GElf_Rela *rela)
{
  GElf_Addr value;
  GElf_Word r_sym;

  if (GELF_R_TYPE (r_info) == R_MIPS_REL32)
    {
      r_sym = GELF_R_SYM (r_info);
      if (r_sym < dso->info_DT_MIPS_GOTSYM)
	{
	  /* glibc's dynamic linker adds the symbol's st_value and the
	     base address to the addend.  It therefore treats all symbols
	     as being relative, even if they would normally be considered
	     absolute.  For example, the special null symbol should always
	     have the value zero, even when the base address is nonzero,
	     but R_MIPS_REL32 relocations against the null symbol must
	     nevertheles be adjusted as if that symbol were relative.
	     The same would apply to SHN_ABS symbols too.

	     Thus the result of the relocation calculation must always
	     be adjusted by ADJUST.  (We do not need to check START because
	     every adjustment requested by the caller will affect all
	     legitimate local relocation values.)  This means that we
	     should add ADJUST to the addend if and only if the symbol's
	     value is not being adjusted.

	     In general, we can only check whether a symbol's value is
	     being adjusted by reading its entry in the dynamic symbol
	     table and then querying adjust_symbol_p.  However, this
	     generality is fortunately not needed.  Modern versions
	     of binutils will never generate R_MIPS_REL32 relocations
	     against symbols in the range [1, DT_MIPS_GOTSYM), so we
	     only need to handle relocations against the null symbol.  */
	  if (r_sym != 0)
	    {
	      error (0, 0, "%s: The prelinker does not support R_MIPS_REL32"
		     " relocs against local symbols", dso->filename);
	      return 1;
	    }
	  value = mips_read_addend (dso, r_offset, rela);
	  mips_write_addend (dso, r_offset, rela, value + adjust);
	}
    }
  return 0;
}

static int
mips_adjust_rel (DSO *dso, GElf_Rel *rel, GElf_Addr start, GElf_Addr adjust)
{
  return mips_adjust_reloc (dso, rel->r_offset, rel->r_info,
			    start, adjust, NULL);
}

static int
mips_adjust_rela (DSO *dso, GElf_Rela *rela, GElf_Addr start, GElf_Addr adjust)
{
  return mips_adjust_reloc (dso, rela->r_offset, rela->r_info,
			    start, adjust, rela);
}

/* Calculate relocation RELA as A + VALUE and store the result in DSO.  */

static void
mips_prelink_32bit_reloc (DSO *dso, GElf_Rela *rela, GElf_Addr value)
{
  assert (rela != NULL);
  write_ne32 (dso, rela->r_offset, value + rela->r_addend);
}

/* There is a relocation of type R_INFO against address R_OFFSET in DSO.
   Prelink the relocation field, using INFO to look up symbol values.
   If the relocation is in a RELA section, RELA points to the relocation,
   otherwise it is null.  */

static int
mips_prelink_reloc (struct prelink_info *info, GElf_Addr r_offset,
		    GElf_Xword r_info, GElf_Rela *rela)
{
  DSO *dso;
  GElf_Addr value;
  GElf_Word r_sym;
  int r_type;

  dso = info->dso;
  r_sym = GELF_R_SYM (r_info);
  r_type = GELF_R_TYPE (r_info);
  switch (r_type)
    {
    case R_MIPS_NONE:
      break;

    case R_MIPS_REL32:
      /* An in-place R_MIPS_REL32 relocation against symbol 0 needs no
	 adjustment.  */
      if (rela != NULL || GELF_R_SYM (r_info) != 0)
	{
	  value = info->resolve (info, r_sym, r_type);
	  mips_prelink_32bit_reloc (dso, rela, value);
	}
      break;

    case R_MIPS_GLOB_DAT:
      write_ne32 (dso, r_offset, info->resolve (info, r_sym, r_type));
      break;

    case R_MIPS_TLS_DTPMOD32:
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  error (0, 0, "%s: R_MIPS_TLS_DTPMOD32 reloc in executable?",
		 dso->filename);
	  return 1;
	}
      /* These relocations will be resolved using a conflict.  We need
	 not change the field value here.  */
      break;

    case R_MIPS_TLS_DTPREL32:
      value = info->resolve (info, r_sym, r_type);
      mips_prelink_32bit_reloc (dso, rela, value - TLS_DTV_OFFSET);
      break;

    case R_MIPS_TLS_TPREL32:
      /* Relocations in a shared library will be resolved using a conflict.
	 We need not change the relocation field here.  */
      if (dso->ehdr.e_type == ET_EXEC)
	{
	  value = info->resolve (info, r_sym, r_type);
	  value += info->resolvetls->offset - TLS_TP_OFFSET;
	  mips_prelink_32bit_reloc (dso, rela, value);
	}
      break;

    default:
      error (0, 0, "%s: Unknown MIPS relocation type %d",
	     dso->filename, (int) GELF_R_TYPE (r_info));
      return 1;
    }
  return 0;
}

static int
mips_prelink_rel (struct prelink_info *info, GElf_Rel *rel, GElf_Addr reladdr)
{
  DSO *dso;

  /* Convert R_MIPS_REL32 relocations against global symbols into
     R_MIPS_GLOB_DAT if the addend is zero.  */
  dso = info->dso;
  if (GELF_R_TYPE (rel->r_info) == R_MIPS_REL32
      && GELF_R_SYM (rel->r_info) >= dso->info_DT_MIPS_GOTSYM
      && read_une32 (dso, rel->r_offset) == 0)
    {
      rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_MIPS_GLOB_DAT);
      write_ne32 (dso, rel->r_offset,
		  info->resolve (info, GELF_R_SYM (rel->r_info),
				 GELF_R_TYPE (rel->r_info)));
      return 2;
    }
  return mips_prelink_reloc (info, rel->r_offset, rel->r_info, NULL);
}

static int
mips_prelink_rela (struct prelink_info *info, GElf_Rela *rela,
		   GElf_Addr relaaddr)
{
  return mips_prelink_reloc (info, rela->r_offset, rela->r_info, rela);
}

/* CONFLICT is a conflict returned by prelink_conflict for a symbol
   belonging to DSO.  Set *TLS_OUT to the associated TLS information.
   Return 1 on failure.  */

static int
mips_get_tls (DSO *dso, struct prelink_conflict *conflict,
	      struct prelink_tls **tls_out)
{
  if (conflict->reloc_class != RTYPE_CLASS_TLS
      || conflict->lookup.tls == NULL)
    {
      error (0, 0, "%s: R_MIPS_TLS not resolving to STT_TLS symbol",
	     dso->filename);
      return 1;
    }

  *tls_out = conflict->lookup.tls;
  return 0;
}

/* There is a relocation of type R_INFO against address R_OFFSET in DSO.
   See if the relocation field must be adjusted by a conflict when DSO
   is used in the context described by INFO.  Add a conflict entry if so.
   If the relocation is in a RELA section, RELA points to the relocation,
   otherwise it is null.  */

static int
mips_prelink_conflict_reloc (DSO *dso, struct prelink_info *info,
			     GElf_Addr r_offset, GElf_Xword r_info,
			     GElf_Rela *rela)
{
  GElf_Addr value;
  struct prelink_conflict *conflict;
  struct prelink_tls *tls;
  GElf_Rela *entry;

  conflict = prelink_conflict (info, GELF_R_SYM (r_info),
			       GELF_R_TYPE (r_info));
  if (conflict == NULL)
    {
      switch (GELF_R_TYPE (r_info))
	{
	case R_MIPS_TLS_DTPMOD32:
	case R_MIPS_TLS_TPREL32:
	  tls = info->curtls;
	  if (tls == NULL)
	    return 0;
	  /* A relocation against symbol 0.  A shared library cannot
	     know what the final module IDs or TP-relative offsets are,
	     so the executable must always have a conflict for them.  */
	  value = 0;
	  break;
	default:
	  return 0;
	}
    }
  else
    {
      /* DTPREL32 relocations just involve the symbol value; no other
	 TLS information is needed.  Ignore conflicts created from a
	 lookup of type RTYPE_CLASS_TLS if no real conflict exists.  */
      if (GELF_R_TYPE (r_info) == R_MIPS_TLS_DTPREL32
	  && conflict->lookup.tls == conflict->conflict.tls
	  && conflict->lookupval == conflict->conflictval)
	return 0;

      value = conflict_lookup_value (conflict);
    }
  /* VALUE now contains the final symbol value.  Change it to the
     value we want to store at R_OFFSET.  */
  switch (GELF_R_TYPE (r_info))
    {
    case R_MIPS_REL32:
      value += mips_read_addend (dso, r_offset, rela);
      break;

    case R_MIPS_GLOB_DAT:
      break;

    case R_MIPS_TLS_DTPMOD32:
      if (conflict != NULL && mips_get_tls (dso, conflict, &tls) == 1)
	return 1;
      value = tls->modid;
      break;

    case R_MIPS_TLS_DTPREL32:
      value += mips_read_addend (dso, r_offset, rela) - TLS_DTV_OFFSET;
      break;

    case R_MIPS_TLS_TPREL32:
      if (conflict != NULL && mips_get_tls (dso, conflict, &tls) == 1)
	return 1;
      value += (mips_read_addend (dso, r_offset, rela)
		+ tls->offset - TLS_TP_OFFSET);
      break;

    default:
      error (0, 0, "%s: Unknown MIPS relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (r_info));
      return 1;
    }
  /* Create and initialize a conflict entry.  */
  entry = prelink_conflict_add_rela (info);
  if (entry == NULL)
    return 1;
  entry->r_addend = (int32_t) value;
  entry->r_offset = r_offset;
  entry->r_info = GELF_R_INFO (0, R_MIPS_REL32);
  return 0;
}

static int
mips_prelink_conflict_rel (DSO *dso, struct prelink_info *info,
			   GElf_Rel *rel, GElf_Addr reladdr)
{
  return mips_prelink_conflict_reloc (dso, info, rel->r_offset,
				      rel->r_info, NULL);
}

static int
mips_prelink_conflict_rela (DSO *dso, struct prelink_info *info,
			    GElf_Rela *rela, GElf_Addr relaaddr)
{
  return mips_prelink_conflict_reloc (dso, info, rela->r_offset,
				      rela->r_info, rela);
}

static int
mips_arch_prelink_conflict (DSO *dso, struct prelink_info *info)
{
  struct mips_global_got_iterator ggi;
  GElf_Addr value;
  struct prelink_conflict *conflict;
  GElf_Rela *entry;

  if (dso->info[DT_PLTGOT] == 0)
    return 0;

  /* Add a conflict for every global GOT entry that does not hold the
     right value, either because of a conflict, or because the DSO has
     a lazy binding stub for a symbol that it also defines.  */
  mips_init_global_got_iterator (&ggi, dso);
  while (mips_get_global_got_entry (&ggi))
    {
      conflict = prelink_conflict (info, ggi.sym_index, R_MIPS_REL32);
      if (conflict != NULL)
	value = conflict_lookup_value (conflict);
      else if (ggi.sym.st_shndx != SHN_UNDEF
	       && ggi.sym.st_shndx != SHN_COMMON)
	value = ggi.sym.st_value;
      else
	continue;
      if (buf_read_une32 (dso, ggi.got_entry) != value)
	{
	  entry = prelink_conflict_add_rela (info);
	  if (entry == NULL)
	    return 1;
	  entry->r_addend = (int32_t) value;
	  entry->r_offset = ggi.got_addr;
	  entry->r_info = GELF_R_INFO (0, R_MIPS_REL32);
	}
    }

  return ggi.failed;
}

static int
mips_apply_conflict_rela (struct prelink_info *info, GElf_Rela *rela,
			  char *buf)
{
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_MIPS_REL32:
      buf_write_ne32 (info->dso, buf, rela->r_addend);
      break;

    default:
      abort ();
    }
  return 0;
}

/* BUF points to a 32-bit field in DSO that is subject to relocation.
   If the relocation is in a RELA section, RELA points to the relocation,
   otherwise it is null.  Add the addend to ADJUSTMENT and install the
   result.  */

static inline void
mips_apply_adjustment (DSO *dso, GElf_Rela *rela, char *buf,
		       GElf_Addr adjustment)
{
  if (rela)
    adjustment += rela->r_addend;
  else
    adjustment += buf_read_une32 (dso, buf);
  buf_write_ne32 (dso, buf, adjustment);
}

static int
mips_apply_reloc (struct prelink_info *info, GElf_Xword r_info,
		  GElf_Rela *rela, char *buf)
{
  DSO *dso;

  dso = info->dso;
  switch (GELF_R_TYPE (r_info))
    {
    case R_MIPS_NONE:
      break;

    case R_MIPS_REL32:
      mips_apply_adjustment (dso, rela, buf,
			     info->resolve (info, GELF_R_SYM (r_info),
					    GELF_R_TYPE (r_info)));
      break;

    default:
      return 1;
    }
  return 0;
}

static int
mips_apply_rel (struct prelink_info *info, GElf_Rel *rel, char *buf)
{
  return mips_apply_reloc (info, rel->r_info, NULL, buf);
}

static int
mips_apply_rela (struct prelink_info *info, GElf_Rela *rela, char *buf)
{
  return mips_apply_reloc (info, rela->r_info, rela, buf);
}

static int
mips_rel_to_rela (DSO *dso, GElf_Rel *rel, GElf_Rela *rela)
{
  rela->r_offset = rel->r_offset;
  rela->r_info = rel->r_info;
  switch (GELF_R_TYPE (rel->r_info))
    {
    case R_MIPS_REL32:
    case R_MIPS_TLS_DTPREL32:
    case R_MIPS_TLS_TPREL32:
      /* These relocations have an in-place addend.  */
      rela->r_addend = (int32_t) read_une32 (dso, rel->r_offset);
      break;

    case R_MIPS_NONE:
    case R_MIPS_GLOB_DAT:
    case R_MIPS_TLS_DTPMOD32:
      /* These relocations have no addend.  */
      rela->r_addend = 0;
      break;

    default:
      error (0, 0, "%s: Unknown MIPS relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rel->r_info));
      return 1;
    }
  return 0;
}

static int
mips_rela_to_rel (DSO *dso, GElf_Rela *rela, GElf_Rel *rel)
{
  rel->r_offset = rela->r_offset;
  rel->r_info = rela->r_info;
  switch (GELF_R_TYPE (rela->r_info))
    {
    case R_MIPS_NONE:
      break;

    case R_MIPS_REL32:
    case R_MIPS_TLS_DTPREL32:
    case R_MIPS_TLS_TPREL32:
      /* These relocations have an in-place addend.  */
      write_ne32 (dso, rela->r_offset, rela->r_addend);
      break;

    case R_MIPS_GLOB_DAT:
    case R_MIPS_TLS_DTPMOD32:
      /* These relocations have no addend.  */
      write_ne32 (dso, rela->r_offset, 0);
      break;

    default:
      error (0, 0, "%s: Unknown MIPS relocation type %d", dso->filename,
	     (int) GELF_R_TYPE (rela->r_info));
      return 1;
    }
  return 0;
}

static int
mips_need_rel_to_rela (DSO *dso, int first, int last)
{
  Elf_Data *data;
  Elf_Scn *scn;
  Elf32_Rel *rel, *relend;
  int n;

  for (n = first; n <= last; n++)
    {
      data = NULL;
      scn = dso->scn[n];
      while ((data = elf_getdata (scn, data)) != NULL)
	{
	  rel = (Elf32_Rel *) data->d_buf;
	  relend = rel + data->d_size / sizeof (Elf32_Rel);
	  for (; rel < relend; rel++)
	    switch (ELF32_R_TYPE (rel->r_info))
	      {
	      case R_MIPS_NONE:
		break;

	      case R_MIPS_REL32:
		/* The SVR4 definition was designed to allow exactly the
		   sort of prelinking we want to do here, in combination
		   with Quickstart.  Unfortunately, glibc's definition
		   makes it impossible for relocations against anything
		   other than the null symbol.  We get around this for
		   zero addends by using a R_MIPS_GLOB_DAT relocation
		   instead, where R_MIPS_GLOB_DAT is a GNU extension
		   added specifically for this purpose.  */
		if (ELF32_R_SYM (rel->r_info) != 0
		    && (ELF32_R_SYM (rel->r_info) < dso->info_DT_MIPS_GOTSYM
			|| read_une32 (dso, rel->r_offset) != 0))
		  return 1;
		break;

	      case R_MIPS_GLOB_DAT:
		/* This relocation has no addend.  */
		break;

	      case R_MIPS_TLS_DTPMOD32:
		/* The relocation will be resolved using a conflict.  */
		break;

	      case R_MIPS_TLS_DTPREL32:
		/* We can prelink these fields, and the addend is relative
		   to the symbol value.  A RELA entry is needed.  */
		return 1;

	      case R_MIPS_TLS_TPREL32:
		/* Relocations in shared libraries will be resolved by a
		   conflict.  Relocations in executables will not, and the
		   addend is relative to the symbol value.  */
		if (dso->ehdr.e_type == ET_EXEC)
		  return 1;
		break;

	      default:
		error (0, 0, "%s: Unknown MIPS relocation type %d",
		       dso->filename, (int) GELF_R_TYPE (rel->r_info));
		return 1;
	      }
	}
    }
  return 0;
}

static int
mips_reloc_size (int reloc_type)
{
  return 4;
}

static int
mips_reloc_class (int reloc_type)
{
  switch (reloc_type)
    {
    case R_MIPS_TLS_DTPMOD32:
    case R_MIPS_TLS_DTPREL32:
    case R_MIPS_TLS_TPREL32:
      return RTYPE_CLASS_TLS;
    default:
      /* MIPS lazy resolution stubs are local to the containing object,
	 so SHN_UNDEF symbols never participate in symbol lookup.  */
      return RTYPE_CLASS_PLT;
    }
}

static int
mips_arch_prelink (struct prelink_info *info)
{
  struct mips_global_got_iterator ggi;
  DSO *dso;
  GElf_Addr value;

  dso = info->dso;
  if (dso->info[DT_PLTGOT] == 0)
    return 0;

  /* Install Quickstart values for all global GOT entries of type A-D
     in the table above.  */
  mips_init_global_got_iterator (&ggi, dso);
  while (mips_get_global_got_entry (&ggi))
    {
      value = info->resolve (info, ggi.sym_index, R_MIPS_REL32);
      if (ggi.sym.st_shndx == SHN_UNDEF
	  || ggi.sym.st_shndx == SHN_COMMON)
	buf_write_ne32 (dso, ggi.got_entry, value);
      else
	{
	  /* Type E and F in the table above.  We cannot install Quickstart
	     values for type E, but we should never need to in executables,
	     because an executable should not use lazy binding stubs for
	     symbols it defines itself.  Although we could in theory just
	     discard any such stub address, it goes against the principle
	     that prelinking should be reversible.

	     When type E entries occur in shared libraries, we can fix
	     them up using conflicts.

	     Type F entries should never need a Quickstart value -- the
	     current value should already be correct.  However, the conflict
	     code will cope correctly with malformed type F entries in
	     shared libraries, so we only complain about executables here.  */
	  if (dso->ehdr.e_type == ET_EXEC
	      && value != buf_read_une32 (dso, ggi.got_entry))
	    {
	      error (0, 0, "%s: The global GOT entries for defined symbols"
		     " do not match their st_values\n", dso->filename);
	      return 1;
	    }
	}
    }
  return ggi.failed;
}

static int
mips_arch_undo_prelink (DSO *dso)
{
  struct mips_global_got_iterator ggi;

  if (dso->info[DT_PLTGOT] == 0)
    return 0;

  mips_init_global_got_iterator (&ggi, dso);
  while (mips_get_global_got_entry (&ggi))
    if (ggi.sym.st_shndx == SHN_UNDEF)
      /* Types A-C in the table above.  */
      buf_write_ne32 (dso, ggi.got_entry, ggi.sym.st_value);
    else if (ggi.sym.st_shndx == SHN_COMMON)
      /* Type D in the table above.  */
      buf_write_ne32 (dso, ggi.got_entry, 0);
  return ggi.failed;
}

static int
mips_undo_prelink_rel (DSO *dso, GElf_Rel *rel, GElf_Addr reladdr)
{
  /* Convert R_MIPS_GLOB_DAT relocations back into R_MIPS_REL32
     relocations.  Ideally we'd have some mechanism for recording
     these changes in the undo section, but in the absence of that,
     it's better to assume that the original relocation was
     R_MIPS_REL32; R_MIPS_GLOB_DAT was added specifically for the
     prelinker and shouldn't be used in non-prelinked binaries.  */
  if (GELF_R_TYPE (rel->r_info) == R_MIPS_GLOB_DAT)
    {
      write_ne32 (dso, rel->r_offset, 0);
      rel->r_info = GELF_R_INFO (GELF_R_SYM (rel->r_info), R_MIPS_REL32);
      return 2;
    }
  return 0;
}

PL_ARCH = {
  .name = "MIPS",
  .class = ELFCLASS32,
  .machine = EM_MIPS,
  .max_reloc_size = 4,
  .dynamic_linker = "/lib/ld.so.1",
  /* MIPS does not use COPY relocs or jump slots.  Pick a value outside
     the ELF32_R_TYPE range.  */
  .R_COPY = ~0U,
  .R_JMP_SLOT = ~0U,
  /* R_MIPS_REL32 relocations against symbol 0 do act as relative relocs,
     but those against other symbols don't.  */
  .R_RELATIVE = ~0U,
  .arch_adjust = mips_arch_adjust,
  .adjust_dyn = mips_adjust_dyn,
  .adjust_rel = mips_adjust_rel,
  .adjust_rela = mips_adjust_rela,
  .prelink_rel = mips_prelink_rel,
  .prelink_rela = mips_prelink_rela,
  .prelink_conflict_rel = mips_prelink_conflict_rel,
  .prelink_conflict_rela = mips_prelink_conflict_rela,
  .arch_prelink_conflict = mips_arch_prelink_conflict,
  .apply_conflict_rela = mips_apply_conflict_rela,
  .apply_rel = mips_apply_rel,
  .apply_rela = mips_apply_rela,
  .rel_to_rela = mips_rel_to_rela,
  .rela_to_rel = mips_rela_to_rel,
  .need_rel_to_rela = mips_need_rel_to_rela,
  .reloc_size = mips_reloc_size,
  .reloc_class = mips_reloc_class,
  .arch_prelink = mips_arch_prelink,
  .arch_undo_prelink = mips_arch_undo_prelink,
  .undo_prelink_rel = mips_undo_prelink_rel,
  /* Although TASK_UNMAPPED_BASE is 0x2aaa8000, we leave some
     area so that mmap of /etc/ld.so.cache and ld.so's malloc
     does not take some library's VA slot.
     Also, if this guard area isn't too small, typically
     even dlopened libraries will get the slots they desire.  */
  .mmap_base = 0x2c000000,
  .mmap_end =  0x3c000000,
  .max_page_size = 0x10000,
  .page_size = 0x1000
};
