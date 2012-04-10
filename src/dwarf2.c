/* Copyright (C) 2001, 2002, 2003, 2005, 2006, 2009, 2010, 2011, 2012
   Red Hat, Inc.
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
#include <errno.h>
#include <error.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>

#include "dwarf2.h"
#include "hashtab.h"
#include "prelink.h"

#define read_uleb128(ptr) ({		\
  unsigned int ret = 0;			\
  unsigned int c;			\
  int shift = 0;			\
  do					\
    {					\
      c = *ptr++;			\
      ret |= (c & 0x7f) << shift;	\
      shift += 7;			\
    } while (c & 0x80);			\
					\
  if (shift >= 35)			\
    ret = UINT_MAX;			\
  ret;					\
})

static uint16_t (*do_read_16) (unsigned char *ptr);
static uint32_t (*do_read_32) (unsigned char *ptr);
static uint64_t (*do_read_32_64) (unsigned char *ptr);
static uint64_t (*do_read_64) (unsigned char *ptr);
static uint64_t (*do_read_ptr) (unsigned char *ptr);
static void (*write_32) (unsigned char *ptr, GElf_Addr val);
static void (*write_64) (unsigned char *ptr, GElf_Addr val);
static void (*write_ptr) (unsigned char *ptr, GElf_Addr val);

static int ptr_size;

#define read_1(ptr) *ptr++

#define read_16(ptr) ({			\
  uint16_t ret = do_read_16 (ptr);	\
  ptr += 2;				\
  ret;					\
})

#define read_32(ptr) ({			\
  uint32_t ret = do_read_32 (ptr);	\
  ptr += 4;				\
  ret;					\
})

#define read_64(ptr) ({			\
  uint64_t ret = do_read_64 (ptr);	\
  ptr += 8;				\
  ret;					\
})

#define read_ptr(ptr) ({		\
  uint64_t ret = do_read_ptr (ptr);	\
  ptr += ptr_size;			\
  ret;					\
})

static uint64_t
buf_read_ule32_64 (unsigned char *p)
{
  return buf_read_ule32 (p);
}

static uint64_t
buf_read_ube32_64 (unsigned char *p)
{
  return buf_read_ube32 (p);
}

static void
dwarf2_write_le32 (unsigned char *p, GElf_Addr val)
{
  uint32_t v = (uint32_t) val;

  p[0] = v;
  p[1] = v >> 8;
  p[2] = v >> 16;
  p[3] = v >> 24;
}

static void
dwarf2_write_le64 (unsigned char *p, GElf_Addr val)
{
  p[0] = val;
  p[1] = val >> 8;
  p[2] = val >> 16;
  p[3] = val >> 24;
  p[4] = val >> 32;
  p[5] = val >> 40;
  p[6] = val >> 48;
  p[7] = val >> 56;
}

static void
dwarf2_write_be32 (unsigned char *p, GElf_Addr val)
{
  uint32_t v = (uint32_t) val;

  p[3] = v;
  p[2] = v >> 8;
  p[1] = v >> 16;
  p[0] = v >> 24;
}

static void
dwarf2_write_be64 (unsigned char *p, GElf_Addr val)
{
  p[7] = val;
  p[6] = val >> 8;
  p[5] = val >> 16;
  p[4] = val >> 24;
  p[3] = val >> 32;
  p[2] = val >> 40;
  p[1] = val >> 48;
  p[0] = val >> 56;
}

static struct
  {
    const char *name;
    unsigned char *data;
    size_t size;
    int sec;
  } debug_sections[] =
  {
#define DEBUG_INFO	0
#define DEBUG_ABBREV	1
#define DEBUG_LINE	2
#define DEBUG_ARANGES	3
#define DEBUG_PUBNAMES	4
#define DEBUG_PUBTYPES	5
#define DEBUG_MACINFO	6
#define DEBUG_LOC	7
#define DEBUG_STR	8
#define DEBUG_FRAME	9
#define DEBUG_RANGES	10
#define DEBUG_TYPES	11
#define DEBUG_MACRO	12
    { ".debug_info", NULL, 0, 0 },
    { ".debug_abbrev", NULL, 0, 0 },
    { ".debug_line", NULL, 0, 0 },
    { ".debug_aranges", NULL, 0, 0 },
    { ".debug_pubnames", NULL, 0, 0 },
    { ".debug_pubtypes", NULL, 0, 0 },
    { ".debug_macinfo", NULL, 0, 0 },
    { ".debug_loc", NULL, 0, 0 },
    { ".debug_str", NULL, 0, 0 },
    { ".debug_frame", NULL, 0, 0 },
    { ".debug_ranges", NULL, 0, 0 },
    { ".debug_types", NULL, 0, 0 },
    { ".debug_macro", NULL, 0, 0 },
    { NULL, NULL, 0 }
  };

struct abbrev_attr
  {
    unsigned int attr;
    unsigned int form;
  };

struct abbrev_tag
  {
    unsigned int entry;
    unsigned int tag;
    int nattr;
    struct abbrev_attr attr[0];
  };

struct cu_data
  {
    GElf_Addr cu_entry_pc;
    GElf_Addr cu_low_pc;
    unsigned char cu_version;
  };

static hashval_t
abbrev_hash (const void *p)
{
  struct abbrev_tag *t = (struct abbrev_tag *)p;

  return t->entry;
}

static int
abbrev_eq (const void *p, const void *q)
{
  struct abbrev_tag *t1 = (struct abbrev_tag *)p;
  struct abbrev_tag *t2 = (struct abbrev_tag *)q;

  return t1->entry == t2->entry;
}

static void
abbrev_del (void *p)
{
  free (p);
}

static htab_t
read_abbrev (DSO *dso, unsigned char *ptr)
{
  htab_t h = htab_try_create (50, abbrev_hash, abbrev_eq, abbrev_del);
  unsigned int attr, form;
  struct abbrev_tag *t;
  int size;
  void **slot;

  if (h == NULL)
    {
no_memory:
      error (0, ENOMEM, "%s: Could not read .debug_abbrev", dso->filename);
      if (h)
	htab_delete (h);
      return NULL;
    }

  while ((attr = read_uleb128 (ptr)) != 0)
    {
      size = 10;
      t = malloc (sizeof (*t) + size * sizeof (struct abbrev_attr));
      if (t == NULL)
	goto no_memory;
      t->entry = attr;
      t->nattr = 0;
      slot = htab_find_slot (h, t, INSERT);
      if (slot == NULL)
	{
	  free (t);
	  goto no_memory;
	}
      if (*slot != NULL)
	{
	  error (0, 0, "%s: Duplicate DWARF abbreviation %d", dso->filename,
		 t->entry);
	  free (t);
	  htab_delete (h);
	  return NULL;
	}
      t->tag = read_uleb128 (ptr);
      ++ptr; /* skip children flag.  */
      while ((attr = read_uleb128 (ptr)) != 0)
	{
	  if (t->nattr == size)
	    {
	      size += 10;
	      t = realloc (t, sizeof (*t) + size * sizeof (struct abbrev_attr));
	      if (t == NULL)
		goto no_memory;
	    }
	  form = read_uleb128 (ptr);
	  if (form == 2
	      || (form > DW_FORM_flag_present && form != DW_FORM_ref_sig8))
	    {
	      error (0, 0, "%s: Unknown DWARF DW_FORM_%d", dso->filename, form);
	      htab_delete (h);
	      return NULL;
	    }

	  t->attr[t->nattr].attr = attr;
	  t->attr[t->nattr++].form = form;
	}
      if (read_uleb128 (ptr) != 0)
	{
	  error (0, 0, "%s: DWARF abbreviation does not end with 2 zeros",
		 dso->filename);
	  htab_delete (h);
	  return NULL;
	}
      *slot = t;
    }

  return h;
}

static int
adjust_location_list (DSO *dso, struct cu_data *cu, unsigned char *ptr,
		      size_t len, GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *end = ptr + len;
  unsigned char op;
  GElf_Addr addr;

  while (ptr < end)
    {
      op = *ptr++;
      switch (op)
	{
	case DW_OP_addr:
	  addr = read_ptr (ptr);
	  if (addr >= start && addr_to_sec (dso, addr) != -1)
	    write_ptr (ptr - ptr_size, addr + adjust);
	  break;
	case DW_OP_deref:
	case DW_OP_dup:
	case DW_OP_drop:
	case DW_OP_over:
	case DW_OP_swap:
	case DW_OP_rot:
	case DW_OP_xderef:
	case DW_OP_abs:
	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_eq:
	case DW_OP_ge:
	case DW_OP_gt:
	case DW_OP_le:
	case DW_OP_lt:
	case DW_OP_ne:
	case DW_OP_lit0 ... DW_OP_lit31:
	case DW_OP_reg0 ... DW_OP_reg31:
	case DW_OP_nop:
	case DW_OP_push_object_address:
	case DW_OP_form_tls_address:
	case DW_OP_call_frame_cfa:
	case DW_OP_stack_value:
	case DW_OP_GNU_push_tls_address:
	case DW_OP_GNU_uninit:
	  break;
	case DW_OP_const1u:
	case DW_OP_pick:
	case DW_OP_deref_size:
	case DW_OP_xderef_size:
	case DW_OP_const1s:
	  ++ptr;
	  break;
	case DW_OP_const2u:
	case DW_OP_const2s:
	case DW_OP_skip:
	case DW_OP_bra:
	case DW_OP_call2:
	  ptr += 2;
	  break;
	case DW_OP_const4u:
	case DW_OP_const4s:
	case DW_OP_call4:
	case DW_OP_GNU_parameter_ref:
	  ptr += 4;
	  break;
	case DW_OP_call_ref:
	  if (cu == NULL)
	    {
	      error (0, 0, "%s: DWARF DW_OP_call_ref shouldn't appear"
		     " in .debug_frame", dso->filename);
	      return 1;
	    }
	  if (cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  break;
	case DW_OP_const8u:
	case DW_OP_const8s:
	  ptr += 8;
	  break;
	case DW_OP_constu:
	case DW_OP_plus_uconst:
	case DW_OP_regx:
	case DW_OP_piece:
	case DW_OP_consts:
	case DW_OP_breg0 ... DW_OP_breg31:
	case DW_OP_fbreg:
	case DW_OP_GNU_convert:
	case DW_OP_GNU_reinterpret:
	  read_uleb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	case DW_OP_GNU_regval_type:
	  read_uleb128 (ptr);
	  read_uleb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_implicit_pointer:
	  if (cu == NULL)
	    {
	      error (0, 0, "%s: DWARF DW_OP_GNU_implicit_pointer shouldn't"
		     " appear in .debug_frame", dso->filename);
	      return 1;
	    }
	  if (cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  read_uleb128 (ptr);
	  break;
        case DW_OP_GNU_entry_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    if ((end - ptr) < leni)
	      {
		error (0, 0, "%s: DWARF DW_OP_GNU_entry_value with too large"
		       " length", dso->filename);
		return 1;
	      }
	    if (adjust_location_list (dso, cu, ptr, leni, start, adjust))
	      return 1;
	    ptr += leni;
	  }
	  break;
        case DW_OP_GNU_const_type:
	  read_uleb128 (ptr);
	  ptr += *ptr + 1;
	  break;
	case DW_OP_GNU_deref_type:
	  ++ptr;
	  read_uleb128 (ptr);
	  break;
	default:
	  error (0, 0, "%s: Unknown DWARF DW_OP_%d", dso->filename, op);
	  return 1;
	}
    }
  return 0;
}

static int
adjust_dwarf2_ranges (DSO *dso, GElf_Addr offset, GElf_Addr base,
		      GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  int adjusted_base;

  ptr = debug_sections[DEBUG_RANGES].data;
  if (ptr == NULL)
    {
      error (0, 0, "%s: DW_AT_ranges attribute, yet no .debug_ranges section",
	     dso->filename);
      return 1;
    }
  if (offset >= debug_sections[DEBUG_RANGES].size)
    {
      error (0, 0,
	     "%s: DW_AT_ranges offset %Ld outside of .debug_ranges section",
	     dso->filename, (long long) offset);
      return 1;
    }
  endsec = ptr + debug_sections[DEBUG_RANGES].size;
  ptr += offset;
  adjusted_base = (base && base >= start && addr_to_sec (dso, base) != -1);
  while (ptr < endsec)
    {
      low = read_ptr (ptr);
      high = read_ptr (ptr);
      if (low == 0 && high == 0)
	break;

      if (low == ~ (GElf_Addr) 0 || (ptr_size == 4 && low == 0xffffffff))
	{
	  base = high;
	  adjusted_base = (base && base >= start
			   && addr_to_sec (dso, base) != -1);
	  if (adjusted_base)
	    write_ptr (ptr - ptr_size, base + adjust);
	}
      else if (! adjusted_base)
	{
	  if (base + low >= start && addr_to_sec (dso, base + low) != -1)
	    {
	      write_ptr (ptr - 2 * ptr_size, low + adjust);
	      if (high == low)
		write_ptr (ptr - ptr_size, high + adjust);
	    }
	  if (low != high && base + high >= start
	      && addr_to_sec (dso, base + high - 1) != -1)
	    write_ptr (ptr - ptr_size, high + adjust);
	}
    }

  elf_flagscn (dso->scn[debug_sections[DEBUG_RANGES].sec], ELF_C_SET,
	       ELF_F_DIRTY);
  return 0;
}

static int
adjust_dwarf2_loc (DSO *dso, struct cu_data *cu, GElf_Addr offset,
		   GElf_Addr base, GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  int adjusted_base;
  size_t len;

  ptr = debug_sections[DEBUG_LOC].data;
  if (ptr == NULL)
    {
      error (0, 0, "%s: loclistptr attribute, yet no .debug_loc section",
	     dso->filename);
      return 1;
    }
  if (offset >= debug_sections[DEBUG_LOC].size)
    {
      error (0, 0,
	     "%s: loclistptr offset %Ld outside of .debug_loc section",
	     dso->filename, (long long) offset);
      return 1;
    }
  endsec = ptr + debug_sections[DEBUG_LOC].size;
  ptr += offset;
  adjusted_base = (base && base >= start && addr_to_sec (dso, base) != -1);
  while (ptr < endsec)
    {
      low = read_ptr (ptr);
      high = read_ptr (ptr);
      if (low == 0 && high == 0)
	break;

      if (low == ~ (GElf_Addr) 0 || (ptr_size == 4 && low == 0xffffffff))
	{
	  base = high;
	  adjusted_base = (base && base >= start
			   && addr_to_sec (dso, base) != -1);
	  if (adjusted_base)
	    write_ptr (ptr - ptr_size, base + adjust);
	  continue;
	}
      len = read_16 (ptr);
      assert (ptr + len <= endsec);

      if (adjust_location_list (dso, cu, ptr, len, start, adjust))
	return 1;

      ptr += len;
    }

  elf_flagscn (dso->scn[debug_sections[DEBUG_LOC].sec], ELF_C_SET,
	       ELF_F_DIRTY);
  return 0;
}

static unsigned char *
adjust_attributes (DSO *dso, unsigned char *ptr, struct abbrev_tag *t,
		   struct cu_data *cu,
		   GElf_Addr start, GElf_Addr adjust)
{
  int i;
  GElf_Addr addr;

  for (i = 0; i < t->nattr; ++i)
    {
      uint32_t form = t->attr[i].form;
      uint32_t len = 0;

      while (1)
	{
	  switch (t->attr[i].attr)
	    {
	    case DW_AT_data_member_location:
	      /* In DWARF4+ DW_AT_data_member_location
		 with DW_FORM_data[48] is just very high
		 constant, rather than loclistptr.  */
	      if (cu->cu_version >= 4 && form != DW_FORM_sec_offset)
		break;
	      /* FALLTHRU */
	    case DW_AT_location:
	    case DW_AT_string_length:
	    case DW_AT_return_addr:
	    case DW_AT_frame_base:
	    case DW_AT_segment:
	    case DW_AT_static_link:
	    case DW_AT_use_location:
	    case DW_AT_vtable_elem_location:
	    case DW_AT_ranges:
	      if (form == DW_FORM_data4 || form == DW_FORM_sec_offset)
		addr = read_32 (ptr), ptr -= 4;
	      else if (form == DW_FORM_data8)
		addr = read_64 (ptr), ptr -= 8;
	      else
		break;
	      {
		GElf_Addr base;

		if (cu->cu_entry_pc != ~ (GElf_Addr) 0)
		  base = cu->cu_entry_pc;
		else if (cu->cu_low_pc != ~ (GElf_Addr) 0)
		  base = cu->cu_low_pc;
	  	else
		  base = 0;
		if (t->attr[i].attr == DW_AT_ranges)
		  {
		    if (adjust_dwarf2_ranges (dso, addr, base, start, adjust))
		      return NULL;
		  }
		else
		  {
		    if (adjust_dwarf2_loc (dso, cu, addr, base, start, adjust))
		      return NULL;
		  }
	      }
	      break;
	    }
	  switch (form)
	    {
	    case DW_FORM_addr:
	      addr = read_ptr (ptr);
	      if (t->tag == DW_TAG_compile_unit
		  || t->tag == DW_TAG_partial_unit)
		{
		  if (t->attr[i].attr == DW_AT_entry_pc)
		    cu->cu_entry_pc = addr;
		  else if (t->attr[i].attr == DW_AT_low_pc)
		    cu->cu_low_pc = addr;
		  if (addr == 0)
		    break;
		}
	      if (addr >= start && addr_to_sec (dso, addr) != -1)
		write_ptr (ptr - ptr_size, addr + adjust);
	      break;
	    case DW_FORM_flag_present:
	      break;
	    case DW_FORM_ref1:
	    case DW_FORM_flag:
	    case DW_FORM_data1:
	      ++ptr;
	      break;
	    case DW_FORM_ref2:
	    case DW_FORM_data2:
	      ptr += 2;
	      break;
	    case DW_FORM_ref4:
	    case DW_FORM_data4:
	    case DW_FORM_sec_offset:
	      ptr += 4;
	      break;
	    case DW_FORM_ref8:
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      ptr += 8;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_ref_udata:
	    case DW_FORM_udata:
	      read_uleb128 (ptr);
	      break;
	    case DW_FORM_ref_addr:
	      if (cu->cu_version == 2)
		ptr += ptr_size;
	      else
		ptr += 4;
	      break;
	    case DW_FORM_strp:
	      ptr += 4;
	      break;
	    case DW_FORM_string:
	      ptr = strchr (ptr, '\0') + 1;
	      break;
	    case DW_FORM_indirect:
	      form = read_uleb128 (ptr);
	      continue;
	    case DW_FORM_block1:
	      len = *ptr++;
	      break;
	    case DW_FORM_block2:
	      len = read_16 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block4:
	      len = read_32 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block:
	      len = read_uleb128 (ptr);
	      form = DW_FORM_block1;
	      assert (len < UINT_MAX);
	      break;
	    case DW_FORM_exprloc:
	      len = read_uleb128 (ptr);
	      assert (len < UINT_MAX);
	      break;
	    default:
	      error (0, 0, "%s: Unknown DWARF DW_FORM_%d", dso->filename,
		     form);
	      return NULL;
	    }

	  if (form == DW_FORM_block1)
	    {
	      switch (t->attr[i].attr)
		{
		case DW_AT_frame_base:
		case DW_AT_location:
		case DW_AT_data_member_location:
		case DW_AT_vtable_elem_location:
		case DW_AT_byte_size:
		case DW_AT_bit_offset:
		case DW_AT_bit_size:
		case DW_AT_string_length:
		case DW_AT_lower_bound:
		case DW_AT_return_addr:
		case DW_AT_bit_stride:
		case DW_AT_upper_bound:
		case DW_AT_count:
		case DW_AT_segment:
		case DW_AT_static_link:
		case DW_AT_use_location:
		case DW_AT_allocated:
		case DW_AT_associated:
		case DW_AT_data_location:
		case DW_AT_byte_stride:
		case DW_AT_GNU_call_site_value:
		case DW_AT_GNU_call_site_data_value:
		case DW_AT_GNU_call_site_target:
		case DW_AT_GNU_call_site_target_clobbered:
		  if (adjust_location_list (dso, cu, ptr, len, start, adjust))
		    return NULL;
		  break;
		default:
		  if (t->attr[i].attr <= DW_AT_linkage_name
		      || (t->attr[i].attr >= DW_AT_MIPS_fde
			  && t->attr[i].attr <= DW_AT_MIPS_has_inlines)
		      || (t->attr[i].attr >= DW_AT_sf_names
			  && t->attr[i].attr <= DW_AT_body_end))
		    break;
		  error (0, 0, "%s: Unknown DWARF DW_AT_%d with block DW_FORM",
			 dso->filename, t->attr[i].attr);
		  return NULL;
		}
	      ptr += len;
	    }
	  else if (form == DW_FORM_exprloc)
	    {
	      if (adjust_location_list (dso, cu, ptr, len, start, adjust))
		return NULL;
	      ptr += len;
	    }

	  break;
	}
    }

  return ptr;
}

static int
adjust_dwarf2_line (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *ptr = debug_sections[DEBUG_LINE].data;
  unsigned char *endsec = ptr + debug_sections[DEBUG_LINE].size;
  unsigned char *endcu, *endprol;
  unsigned char opcode_base, *opcode_lengths, op;
  uint32_t value;
  GElf_Addr addr;
  int i;

  while (ptr < endsec)
    {
      endcu = ptr + 4;
      endcu += read_32 (ptr);
      if (endcu == ptr + 0xffffffff)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  return 1;
	}

      if (endcu > endsec)
	{
	  error (0, 0, "%s: .debug_line CU does not fit into section",
		 dso->filename);
	  return 1;
	}

      value = read_16 (ptr);
      if (value != 2 && value != 3 && value != 4)
	{
	  error (0, 0, "%s: DWARF version %d unhandled", dso->filename,
		 value);
	  return 1;
	}

      endprol = ptr + 4;
      endprol += read_32 (ptr);
      if (endprol > endcu)
	{
	  error (0, 0, "%s: .debug_line CU prologue does not fit into CU",
		 dso->filename);
	  return 1;
	}

      opcode_base = ptr[4 + (value >= 4)];
      opcode_lengths = ptr + 4 + (value >= 4);

      ptr = endprol;
      while (ptr < endcu)
	{
	  op = *ptr++;
	  if (op >= opcode_base)
	    continue;
	  if (op == DW_LNS_extended_op)
	    {
	      unsigned int len = read_uleb128 (ptr);

	      assert (len < UINT_MAX);
	      op = *ptr++;
	      switch (op)
		{
		case DW_LNE_set_address:
		  addr = read_ptr (ptr);
		  if (addr >= start && addr_to_sec (dso, addr) != -1)
		    write_ptr (ptr - ptr_size, addr + adjust);
		  break;
		case DW_LNE_end_sequence:
		case DW_LNE_define_file:
		case DW_LNE_set_discriminator:
		default:
		  ptr += len - 1;
		  break;
		}
	    }
	  else if (op == DW_LNS_fixed_advance_pc)
	    ptr += 2;
	  else
	    for (i = 0; i < opcode_lengths[op]; ++i)
	      read_uleb128 (ptr);
	}
    }

  elf_flagscn (dso->scn[debug_sections[DEBUG_LINE].sec], ELF_C_SET,
	       ELF_F_DIRTY);
  return 0;
}

static int
adjust_dwarf2_aranges (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *ptr = debug_sections[DEBUG_ARANGES].data;
  unsigned char *endsec = ptr + debug_sections[DEBUG_ARANGES].size;
  unsigned char *endcu;
  GElf_Addr addr, len;
  uint32_t value;

  while (ptr < endsec)
    {
      endcu = ptr + 4;
      endcu += read_32 (ptr);
      if (endcu == ptr + 0xffffffff)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  return 1;
	}

      if (endcu > endsec)
	{
	  error (0, 0, "%s: .debug_line CU does not fit into section",
		 dso->filename);
	  return 1;
	}

      value = read_16 (ptr);
      if (value != 2)
	{
	  error (0, 0, "%s: DWARF version %d unhandled", dso->filename,
		 value);
	  return 1;
	}

      ptr += 4;
      if (ptr[0] != ptr_size || ptr[1])
	{
	  error (0, 0, "%s: Unsupported .debug_aranges address size %d or segment size %d",
		 dso->filename, ptr[0], ptr[1]);
	  return 1;
	}

      ptr += 6;
      while (ptr < endcu)
	{
	  addr = read_ptr (ptr);
	  len = read_ptr (ptr);
	  if (addr == 0 && len == 0)
	    break;
	  if (addr >= start && addr_to_sec (dso, addr) != -1)
	    write_ptr (ptr - 2 * ptr_size, addr + adjust);
	}
      assert (ptr == endcu);
    }

  elf_flagscn (dso->scn[debug_sections[DEBUG_LINE].sec], ELF_C_SET,
	       ELF_F_DIRTY);
  return 0;
}

static int
adjust_dwarf2_frame (DSO *dso, GElf_Addr start, GElf_Addr adjust)
{
  unsigned char *ptr = debug_sections[DEBUG_FRAME].data;
  unsigned char *endsec = ptr + debug_sections[DEBUG_FRAME].size;
  unsigned char *endie;
  GElf_Addr addr, len;
  uint32_t value;

  while (ptr < endsec)
    {
      endie = ptr + 4;
      endie += read_32 (ptr);
      if (endie == ptr + 0xffffffff)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  return 1;
	}

      if (endie > endsec)
	{
	  error (0, 0, "%s: .debug_frame CIE/FDE does not fit into section",
		 dso->filename);
	  return 1;
	}

      value = read_32 (ptr);
      if (value == 0xffffffff)
	{
	  /* CIE.  */
	  uint32_t version = *ptr++;
	  if (version != 1 && version != 3 && version != 4)
	    {
	      error (0, 0, "%s: unhandled .debug_frame version %d",
		     dso->filename, version);
	      return 1;
	    }
	  if (*ptr != '\0')
	    {
	      error (0, 0, "%s: .debug_frame unhandled augmentation \"%s\"",
		     dso->filename, ptr);
	      return 1;
	    }
	  ptr++;  /* Skip augmentation.  */
	  if (version >= 4)
	    {
	      if (ptr[0] != ptr_size)
		{
		  error (0, 0, "%s: .debug_frame unhandled pointer size %d",
			  dso->filename, ptr[0]);
		  return 1;
		}
	      if (ptr[1] != 0)
		{
		  error (0, 0, "%s: .debug_frame unhandled non-zero segment size",
			 dso->filename);
		  return 1;
		}
	      ptr += 2;
	    }
	  read_uleb128 (ptr);  /* Skip code_alignment factor.  */
	  read_uleb128 (ptr);  /* Skip data_alignment factor.  */
	  if (version >= 3)
	    read_uleb128 (ptr);  /* Skip return_address_register.  */
	  else
	    ptr++;
	}
      else
	{
	  addr = read_ptr (ptr);
	  if (addr >= start && addr_to_sec (dso, addr) != -1)
	    write_ptr (ptr - ptr_size, addr + adjust);
	  read_ptr (ptr);  /* Skip address range.  */
	}

      while (ptr < endie)
	{
	  unsigned char insn = *ptr++;

	  if ((insn & 0xc0) == DW_CFA_advance_loc
	      || (insn & 0xc0) == DW_CFA_restore)
	    continue;
	  else if ((insn & 0xc0) == DW_CFA_offset)
	    {
	      read_uleb128 (ptr);
	      continue;
	    }
	  switch (insn)
	    {
	    case DW_CFA_nop:
	    case DW_CFA_remember_state:
	    case DW_CFA_restore_state:
	    case DW_CFA_GNU_window_save:
	      break;
	    case DW_CFA_offset_extended:
	    case DW_CFA_register:
	    case DW_CFA_def_cfa:
	    case DW_CFA_offset_extended_sf:
	    case DW_CFA_def_cfa_sf:
	    case DW_CFA_GNU_negative_offset_extended:
	    case DW_CFA_val_offset:
	    case DW_CFA_val_offset_sf:
	      read_uleb128 (ptr);
	      /* FALLTHROUGH */
	    case DW_CFA_restore_extended:
	    case DW_CFA_undefined:
	    case DW_CFA_same_value:
	    case DW_CFA_def_cfa_register:
	    case DW_CFA_def_cfa_offset:
	    case DW_CFA_def_cfa_offset_sf:
	    case DW_CFA_GNU_args_size:
	      read_uleb128 (ptr);
	      break;
	    case DW_CFA_set_loc:
	      addr = read_ptr (ptr);
	      if (addr >= start && addr_to_sec (dso, addr) != -1)
		write_ptr (ptr - ptr_size, addr + adjust);
	      break;
	    case DW_CFA_advance_loc1:
	      ptr++;
	      break;
	    case DW_CFA_advance_loc2:
	      ptr += 2;
	      break;
	    case DW_CFA_advance_loc4:
	      ptr += 4;
	      break;
	    case DW_CFA_expression:
	    case DW_CFA_val_expression:
	      read_uleb128 (ptr);
	      /* FALLTHROUGH */
	    case DW_CFA_def_cfa_expression:
	      len = read_uleb128 (ptr);
	      if (adjust_location_list (dso, NULL, ptr, len, start, adjust))
		return 1;
	      ptr += len;
	      break;
	    default:
	      error (0, 0, "%s: Unhandled DW_CFA_%02x operation",
		     dso->filename, insn);
	      return 1;
	    }
	}
    }

  elf_flagscn (dso->scn[debug_sections[DEBUG_FRAME].sec], ELF_C_SET,
	       ELF_F_DIRTY);
  return 0;
}

static int
adjust_dwarf2_info (DSO *dso, GElf_Addr start, GElf_Addr adjust, int type)
{
  unsigned char *ptr, *endcu, *endsec;
  uint32_t value;
  htab_t abbrev;
  struct abbrev_tag tag, *t;
  struct cu_data cu;

  memset (&cu, 0, sizeof(cu));
  ptr = debug_sections[type].data;
  endsec = ptr + debug_sections[type].size;
  while (ptr < endsec)
    {
      if (ptr + 11 > endsec)
	{
	  error (0, 0, "%s: .debug_info CU header too small", dso->filename);
	  return 1;
	}

      endcu = ptr + 4;
      endcu += read_32 (ptr);
      if (endcu == ptr + 0xffffffff)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  return 1;
	}

      if (endcu > endsec)
	{
	  error (0, 0, "%s: .debug_info too small", dso->filename);
	  return 1;
	}

      value = read_16 (ptr);
      if (value != 2 && value != 3 && value != 4)
	{
	  error (0, 0, "%s: DWARF version %d unhandled", dso->filename, value);
	  return 1;
	}
      cu.cu_version = value;

      value = read_32 (ptr);
      if (value >= debug_sections[DEBUG_ABBREV].size)
	{
	  if (debug_sections[DEBUG_ABBREV].data == NULL)
	    error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	  else
	    error (0, 0, "%s: DWARF CU abbrev offset too large",
		   dso->filename);
	  return 1;
	}

      if (ptr_size == 0)
	{
	  ptr_size = read_1 (ptr);
	  if (ptr_size == 4)
	    {
	      do_read_ptr = do_read_32_64;
	      write_ptr = write_32;
	    }
	  else if (ptr_size == 8)
	    {
	      do_read_ptr = do_read_64;
	      write_ptr = write_64;
	    }
	  else
	    {
	      error (0, 0, "%s: Invalid DWARF pointer size %d",
		     dso->filename, ptr_size);
	      return 1;
	    }
	}
      else if (read_1 (ptr) != ptr_size)
	{
	  error (0, 0, "%s: DWARF pointer size differs between CUs",
		 dso->filename);
	  return 1;
	}

      abbrev = read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value);
      if (abbrev == NULL)
	return 1;

      cu.cu_entry_pc = ~ (GElf_Addr) 0;
      cu.cu_low_pc = ~ (GElf_Addr) 0;

      if (type == DEBUG_TYPES)
	{
	  ptr += 8; /* Skip type_signature.  */
	  ptr += 4; /* Skip type_offset.  */
	}

      while (ptr < endcu)
	{
	  tag.entry = read_uleb128 (ptr);
	  if (tag.entry == 0)
	    continue;
	  t = htab_find_with_hash (abbrev, &tag, tag.entry);
	  if (t == NULL)
	    {
	      error (0, 0, "%s: Could not find DWARF abbreviation %d",
		     dso->filename, tag.entry);
	      htab_delete (abbrev);
	      return 1;
	    }

	  ptr = adjust_attributes (dso, ptr, t, &cu, start, adjust);
	  if (ptr == NULL)
	    {
	      htab_delete (abbrev);
	      return 1;
	    }
	}

      htab_delete (abbrev);
    }
  return 0;
}

int
adjust_dwarf2 (DSO *dso, int n, GElf_Addr start, GElf_Addr adjust)
{
  Elf_Data *data;
  Elf_Scn *scn;
  int i, j;

  for (i = 0; debug_sections[i].name; ++i)
    {
      debug_sections[i].data = NULL;
      debug_sections[i].size = 0;
      debug_sections[i].sec = 0;
    }
  ptr_size = 0;

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    if (! (dso->shdr[i].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR))
	&& dso->shdr[i].sh_size)
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				   dso->shdr[i].sh_name);

	if (strncmp (name, ".debug_", sizeof (".debug_") - 1) == 0)
	  {
	    for (j = 0; debug_sections[j].name; ++j)
	      if (strcmp (name, debug_sections[j].name) == 0)
	 	{
		  if (debug_sections[j].data)
		    {
		      error (0, 0, "%s: Found two copies of %s section",
			     dso->filename, name);
		      return 1;
		    }

		  scn = dso->scn[i];
		  data = elf_getdata (scn, NULL);
		  assert (data != NULL && data->d_buf != NULL);
		  assert (elf_getdata (scn, data) == NULL);
		  assert (data->d_off == 0);
		  assert (data->d_size == dso->shdr[i].sh_size);
		  debug_sections[j].data = data->d_buf;
		  debug_sections[j].size = data->d_size;
		  debug_sections[j].sec = i;
		  break;
		}

	    if (debug_sections[j].name == NULL)
	      {
		error (0, 0, "%s: Unknown debugging section %s",
		       dso->filename, name);
		return 1;
	      }
	  }
      }

  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
    {
      do_read_16 = buf_read_ule16;
      do_read_32 = buf_read_ule32;
      do_read_32_64 = buf_read_ule32_64;
      do_read_64 = buf_read_ule64;
      write_32 = dwarf2_write_le32;
      write_64 = dwarf2_write_le64;
    }
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
    {
      do_read_16 = buf_read_ube16;
      do_read_32 = buf_read_ube32;
      do_read_32_64 = buf_read_ube32_64;
      do_read_64 = buf_read_ube64;
      write_32 = dwarf2_write_be32;
      write_64 = dwarf2_write_be64;
    }
  else
    {
      error (0, 0, "%s: Wrong ELF data enconding", dso->filename);
      return 1;
    }

  if (debug_sections[DEBUG_INFO].data != NULL
      && adjust_dwarf2_info (dso, start, adjust, DEBUG_INFO))
    return 1;

  if (debug_sections[DEBUG_TYPES].data != NULL
      && adjust_dwarf2_info (dso, start, adjust, DEBUG_TYPES))
    return 1;

  if (ptr_size == 0)
    /* Should not happen.  */
    ptr_size = dso->ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? 8 : 4;

  if (debug_sections[DEBUG_LINE].data != NULL
      && adjust_dwarf2_line (dso, start, adjust))
    return 1;

  if (debug_sections[DEBUG_ARANGES].data != NULL
      && adjust_dwarf2_aranges (dso, start, adjust))
    return 1;

  if (debug_sections[DEBUG_FRAME].data != NULL
      && adjust_dwarf2_frame (dso, start, adjust))
    return 1;

  /* .debug_abbrev requires no adjustement.  */
  /* .debug_pubnames requires no adjustement.  */
  /* .debug_pubtypes requires no adjustement.  */
  /* .debug_macinfo requires no adjustement.  */
  /* .debug_str requires no adjustement.  */
  /* .debug_ranges adjusted for each DW_AT_ranges pointing into it.  */
  /* .debug_loc adjusted for each loclistptr pointing into it.  */

  elf_flagscn (dso->scn[n], ELF_C_SET, ELF_F_DIRTY);
  return 0;
}
