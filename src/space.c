/* Copyright (C) 2001, 2002, 2003, 2004, 2006 Red Hat, Inc.
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
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "prelink.h"
#include "reloc.h"
#include "space.h"

#define DEBUG_SECTIONS

#ifdef DEBUG_SECTIONS
void
print_sections (DSO *dso, GElf_Ehdr *ehdr, GElf_Shdr *shdr)
{
  int elf64 = ehdr->e_ident[EI_CLASS] == ELFCLASS64;
  int i, j, shf, flag;
  char buf[32], *q;
  const char *p;
  static struct { int sh_type; const char *type_name; } types[] =
    {
      { SHT_NULL, "NULL" },
      { SHT_PROGBITS, "PROGBITS" },
      { SHT_SYMTAB, "SYMTAB" },
      { SHT_STRTAB, "STRTAB" },
      { SHT_RELA, "RELA" },
      { SHT_HASH, "HASH" },
      { SHT_DYNAMIC, "DYNAMIC" },
      { SHT_NOTE, "NOTE" },
      { SHT_NOBITS, "NOBITS" },
      { SHT_REL, "REL" },
      { SHT_SHLIB, "SHLIB" },
      { SHT_DYNSYM, "DYNSYM" },
      { SHT_INIT_ARRAY, "INIT_ARRAY" },
      { SHT_FINI_ARRAY, "FINI_ARRAY" },
      { SHT_PREINIT_ARRAY, "PREINIT_ARRAY" },
      { SHT_GROUP, "GROUP" },
      { SHT_SYMTAB_SHNDX, "SYMTAB SECTION INDICIES" },
      { SHT_GNU_verdef, "VERDEF" },
      { SHT_GNU_verneed, "VERNEED" },
      { SHT_GNU_versym, "VERSYM" },
      { SHT_GNU_LIBLIST, "LIBLIST" },
      { SHT_GNU_HASH, "GNU_HASH" },
      { 0, NULL }
    };

  if (elf64)
    printf ("  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n");
  else
    printf ("  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n");
  for (i = 0; i < ehdr->e_shnum; ++i)
    {
      p = NULL;
      for (j = 0; types[j].type_name; ++j)
	if (types[j].sh_type == shdr[i].sh_type)
	  {
	    p = types[j].type_name;
	    break;
	  }

      if (p == NULL)
	{
	  if (shdr[i].sh_type >= SHT_LOPROC && shdr[i].sh_type <= SHT_HIPROC)
	    sprintf (buf, "LOPROC+%x", shdr[i].sh_type - SHT_LOPROC);
	  else if (shdr[i].sh_type >= SHT_LOOS && shdr[i].sh_type <= SHT_HIOS)
	    sprintf (buf, "LOOS+%x", shdr[i].sh_type - SHT_LOOS);
	  else if (shdr[i].sh_type >= SHT_LOUSER && shdr[i].sh_type <= SHT_HIUSER)
	    sprintf (buf, "LOUSER+%x", shdr[i].sh_type - SHT_LOUSER);
	  else
	    sprintf (buf, "Unknown: %x", shdr[i].sh_type);
	  p = buf;
	}

      printf ("  [%2d] %-17.17s %-15.15s ", i,
	      strptr (dso, ehdr->e_shstrndx, shdr[i].sh_name), p);

      q = buf;
      shf = shdr[i].sh_flags;
      while (shf)
	{
	  flag = shf & -shf;
	  shf &= ~flag;
	  switch (flag)
	    {
	    case SHF_WRITE:		*q++ = 'W'; break;
	    case SHF_ALLOC:		*q++ = 'A'; break;
	    case SHF_EXECINSTR:		*q++ = 'X'; break;
	    case SHF_MERGE:		*q++ = 'M'; break;
	    case SHF_STRINGS:		*q++ = 'S'; break;
	    case SHF_INFO_LINK:		*q++ = 'I'; break;
	    case SHF_LINK_ORDER:	*q++ = 'L'; break;
	    case SHF_OS_NONCONFORMING:	*q++ = 'O'; break;
	    case SHF_TLS:		*q++ = 'T'; break;
	    default:
	      if (flag & SHF_MASKOS)
		*q++ = 'o', shf &= ~SHF_MASKOS;
	      else if (flag & SHF_MASKPROC)
		*q++ = 'p', shf &= ~SHF_MASKPROC;
	      else
		*q++ = 'x';
	      break;
	    }
	}
      *q = '\0';
      if (elf64)
	printf (" %16.16llx %6.6llx %6.6llx %2.2lx %3s %2ld %3lx %2ld\n",
		(long long) shdr[i].sh_addr, (long long) shdr[i].sh_offset,
		(long long) shdr[i].sh_size, (long) shdr[i].sh_entsize,
		buf, (long) shdr[i].sh_link, (long) shdr[i].sh_info,
		(long) shdr[i].sh_addralign);
      else
	printf (" %8.8lx %6.6lx %6.6lx %2.2lx %3s %2ld %3lx %2ld\n",
		(long) shdr[i].sh_addr, (long) shdr[i].sh_offset,
		(long) shdr[i].sh_size, (long) shdr[i].sh_entsize,
		buf, (long) shdr[i].sh_link, (long) shdr[i].sh_info,
		(long) shdr[i].sh_addralign);
    }
}
#endif

void
insert_readonly_section (GElf_Ehdr *ehdr, GElf_Shdr *shdr, int n,
			 struct readonly_adjust *adjust)
{
  int i;

  memmove (&shdr[n + 1], &shdr[n],
	   (ehdr->e_shnum - n) * sizeof (GElf_Shdr));
  ++ehdr->e_shnum;
  for (i = 0; i < adjust->newcount; ++i)
    if (adjust->new[i] >= n)
      ++adjust->new[i];
}

int
remove_readonly_section (GElf_Ehdr *ehdr, GElf_Shdr *shdr, int n,
			 struct readonly_adjust *adjust)
{
  int i, ret = -1;

  memmove (&shdr[n], &shdr[n + 1],
	   (ehdr->e_shnum - n) * sizeof (GElf_Shdr));
  --ehdr->e_shnum;
  for (i = 0; i < adjust->newcount; ++i)
    if (adjust->new[i] > n)
      --adjust->new[i];
    else if (adjust->new[i] == n)
      {
	adjust->new[i] = -1;
	ret = i;
      }

  return ret;
}

static inline int
readonly_is_movable (DSO *dso, GElf_Ehdr *ehdr, GElf_Shdr *shdr, int k)
{
  if (! (shdr[k].sh_flags & (SHF_ALLOC | SHF_WRITE)))
    return 0;

  switch (shdr[k].sh_type)
    {
    case SHT_HASH:
    case SHT_GNU_HASH:
    case SHT_DYNSYM:
    case SHT_REL:
    case SHT_RELA:
    case SHT_STRTAB:
    case SHT_NOTE:
    case SHT_GNU_verdef:
    case SHT_GNU_verneed:
    case SHT_GNU_versym:
    case SHT_GNU_LIBLIST:
      return 1;
    default:
      if (strcmp (strptr (dso, ehdr->e_shstrndx,
			  shdr[k].sh_name), ".interp") == 0)
	return 1;
      return 0;
    }
}

int
find_readonly_space (DSO *dso, GElf_Shdr *add, GElf_Ehdr *ehdr,
		     GElf_Phdr *phdr, GElf_Shdr *shdr,
		     struct readonly_adjust *adjust)
{
  int i, j;
  GElf_Addr addr;
  GElf_Off p_filesz;

  if (add->sh_addr)
    {
      /* Prefer the current address if possible.  */
      for (i = 0; i < ehdr->e_phnum; ++i)
	if (phdr[i].p_type == PT_LOAD
	    && (phdr[i].p_flags & (PF_R | PF_W)) == PF_R
	    && phdr[i].p_vaddr <= add->sh_addr
	    && phdr[i].p_vaddr + phdr[i].p_filesz
	       >= add->sh_addr + add->sh_size)
	  break;

      if (i < ehdr->e_phnum)
	for (j = 1; j < ehdr->e_shnum; ++j)
	  if ((shdr[j].sh_flags & SHF_ALLOC)
	      && shdr[j].sh_addr >= add->sh_addr)
	    {
	      if (shdr[j].sh_addr >= add->sh_addr + add->sh_size
		  && shdr[j - 1].sh_addr + shdr[j - 1].sh_size <= add->sh_addr)
		{
		  insert_readonly_section (ehdr, shdr, j, adjust);
		  shdr[j] = *add;
		  shdr[j].sh_offset = (shdr[j].sh_addr - phdr[i].p_vaddr)
				       + phdr[i].p_offset;
		  return j;
		}
	      break;
	    }
    }

  for (i = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD
	&& (phdr[i].p_flags & (PF_R | PF_W)) == PF_R)
      {
	GElf_Addr start = phdr[i].p_vaddr;
	int after = -1, min;

	if (phdr[i].p_offset < ehdr->e_phoff)
	  start += ehdr->e_phoff
		   + ehdr->e_phnum * ehdr->e_phentsize
		   - phdr[i].p_offset;
	start = (start + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
	for (j = 1; j < ehdr->e_shnum; ++j)
	  if ((shdr[j].sh_flags & SHF_ALLOC)
	      && shdr[j].sh_addr >= phdr[i].p_vaddr
	      && shdr[j].sh_addr + shdr[j].sh_size
		 <= phdr[i].p_vaddr + phdr[i].p_filesz)
	    {
	      if (after == -1)
		after = j - 1;
	      if (start + add->sh_size > shdr[j].sh_addr)
		{
		  start = shdr[j].sh_addr + shdr[j].sh_size;
		  start = (start + add->sh_addralign - 1)
			  & ~(add->sh_addralign - 1);
		  after = j;
		}
	    }

	min = -1;
	for (j = i + 1; j < ehdr->e_phnum; ++j)
	  if (phdr[j].p_offset >= phdr[i].p_offset + phdr[i].p_filesz
	      && (min == -1 || phdr[min].p_offset > phdr[j].p_offset))
	    min = j;

	if (after != -1
	    && (start + add->sh_size <= phdr[i].p_vaddr + phdr[i].p_filesz
		|| (phdr[i].p_filesz == phdr[i].p_memsz
		    && (min == -1
			|| start + add->sh_size - phdr[i].p_vaddr
			   <= phdr[min].p_offset))))
	  {
	    insert_readonly_section (ehdr, shdr, after + 1, adjust);
	    shdr[after + 1] = *add;
	    shdr[after + 1].sh_addr = start;
	    shdr[after + 1].sh_offset = (start - phdr[i].p_vaddr)
					 + phdr[i].p_offset;
	    if (start + add->sh_size > phdr[i].p_vaddr + phdr[i].p_filesz)
	      {
		adjust_nonalloc (dso, ehdr, shdr, 0, 0,
				 start + add->sh_size - phdr[i].p_vaddr
				 - phdr[i].p_filesz);
		phdr[i].p_filesz = start + add->sh_size - phdr[i].p_vaddr;
		phdr[i].p_memsz = phdr[i].p_filesz;
	      }
	    return after + 1;
	  }
      }

  /* If SHT_NOBITS sections are small, just extend the last PT_LOAD
     segment.  Small enough here means that the whole .bss fits into
     the same CPU page as the alloced part of it.  */
  for (i = -1, j = 0; j < ehdr->e_phnum; ++j)
    if (phdr[j].p_type == PT_LOAD)
      i = j;
  p_filesz = phdr[i].p_filesz;

  /* If we'll be converting NOBITS .plt to PROGBITS, account for that in the
     calculation.  */
  for (j = 1; j < ehdr->e_shnum; ++j)
    {
      if (shdr[j].sh_type == SHT_NOBITS
	  && shdr[j].sh_addr >= phdr[i].p_vaddr
	  && shdr[j].sh_addr + shdr[j].sh_size
	     <= phdr[i].p_vaddr + phdr[i].p_memsz
	  && !strcmp (strptr (dso, ehdr->e_shstrndx, shdr[j].sh_name), ".plt"))
	{
	  if (shdr[j].sh_addr + shdr[j].sh_size - phdr[i].p_vaddr > p_filesz)
	    p_filesz = shdr[j].sh_addr + shdr[j].sh_size - phdr[i].p_vaddr;
	  break;
	}
    }

  if (phdr[i].p_filesz
      && p_filesz <= phdr[i].p_memsz
      && !(((phdr[i].p_vaddr + phdr[i].p_memsz - 1)
	    ^ (phdr[i].p_vaddr + p_filesz - 1)) & ~(dso->arch->page_size - 1)))
    {
      for (j = 1; j < ehdr->e_shnum; ++j)
	{
	  if (!(shdr[j].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_ALLOC)))
	    break;
	  if (shdr[j].sh_type == SHT_NOBITS
	      && (shdr[j].sh_flags & SHF_TLS) == 0
	      && shdr[j].sh_addr >= phdr[i].p_vaddr)
	    shdr[j].sh_type = SHT_PROGBITS;
	}

      insert_readonly_section (ehdr, shdr, j, adjust);
      shdr[j] = *add;
      shdr[j].sh_addr = (shdr[j - 1].sh_addr + shdr[j - 1].sh_size
			 + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
      shdr[j].sh_offset = (shdr[j].sh_addr - phdr[i].p_vaddr)
			  + phdr[i].p_offset;
      phdr[i].p_filesz = shdr[j].sh_addr + add->sh_size - phdr[i].p_vaddr;
      phdr[i].p_memsz = phdr[i].p_filesz;
      adjust_nonalloc (dso, ehdr, shdr, 0, 0, phdr[i].p_offset
		       + phdr[i].p_filesz - shdr[j + 1].sh_offset);
      return j;
    }

  /* See if we can decrease binary's base VMA and thus gain space.
     This trick is mainly useful for IA-32.  */
  for (i = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD)
      break;

  addr = (add->sh_size + add->sh_addralign - 1 + phdr[i].p_align - 1)
	 & ~(phdr[i].p_align - 1);
  if (phdr[i].p_align <= dso->arch->page_size
      && phdr[i].p_flags == (PF_R | PF_X)
      && phdr[i].p_filesz == phdr[i].p_memsz
      && phdr[i].p_vaddr - addr
      && ! (((phdr[i].p_vaddr - addr) ^ phdr[i].p_vaddr)
	    & ~(phdr[i].p_align * 256 - 1)))
    {
      int moveend;
      if (! adjust->basemove_end)
	{
	  for (moveend = 1; moveend < ehdr->e_shnum; ++moveend)
	    if (strcmp (strptr (dso, ehdr->e_shstrndx,
				shdr[moveend].sh_name), ".interp")
		&& shdr[moveend].sh_type != SHT_NOTE)
	      break;
	  if (moveend < ehdr->e_shnum && moveend > 1)
	    {
	      adjust->basemove_end = shdr[moveend].sh_addr;
	      adjust->moveend = moveend;
	    }
	}
      else
	moveend = adjust->moveend;
      if (moveend < ehdr->e_shnum && moveend > 1
	  && (shdr[moveend].sh_flags & (SHF_ALLOC | SHF_WRITE)))
	{
	  int k = moveend;
	  GElf_Addr adj = addr;

	  if (add->sh_addr && ! adjust->move2
	      && phdr[i].p_vaddr <= add->sh_addr
	      && phdr[i].p_vaddr + phdr[i].p_filesz > add->sh_addr)
	    {
	      for (k = moveend; k < ehdr->e_shnum; ++k)
		{
		  if (! (shdr[k].sh_flags & (SHF_ALLOC | SHF_WRITE)))
		    {
		      k = ehdr->e_shnum;
		      break;
		    }

		  if (shdr[k].sh_addr > add->sh_addr)
		    {
		      /* Don't allow inserting in between reloc sections
			 if they are adjacent.  */
		      if (shdr[k].sh_type != SHT_REL
			  && shdr[k].sh_type != SHT_RELA)
			break;
		      if (shdr[k - 1].sh_type != SHT_REL
			  && shdr[k - 1].sh_type != SHT_RELA)
			break;
		      if (shdr[k - 1].sh_addr + shdr[k - 1].sh_size
			  != shdr[k].sh_addr)
			break;
		    }

		  if (! readonly_is_movable (dso, ehdr, shdr, k))
		    {
		      k = ehdr->e_shnum;
		      break;
		    }
		}

	      if (k < ehdr->e_shnum)
		{
		  GElf_Addr a;

		  a = shdr[k].sh_addr;
		  a -= shdr[k - 1].sh_addr + shdr[k - 1].sh_size;
		  assert (add->sh_addralign <= phdr[i].p_align);
		  assert (add->sh_size > a);
		  a = (add->sh_size - a + phdr[i].p_align - 1)
		      & ~(phdr[i].p_align - 1);
		  if (a < adj)
		    {
		      adjust->move2 = 1;
		      adj = a;
		    }
		  else
		    k = moveend;
		}
	      else
		k = moveend;
	    }

	  for (j = 1; j < k; ++j)
	    shdr[j].sh_addr -= adj;
	  phdr[i].p_vaddr -= adj;
	  phdr[i].p_paddr -= adj;
	  phdr[i].p_filesz += adj;
	  phdr[i].p_memsz += adj;
	  for (j = 0; j < ehdr->e_phnum; ++j)
	    {
	      if (j == i)
		continue;
	      /* Leave STACK segment alone, it has p_vaddr == p_paddr == 0
		 and p_offset == p_filesz == p_memsz == 0.  */
	      if (phdr[j].p_type == PT_GNU_STACK)
		continue;
	      if (phdr[j].p_vaddr
		  < adjust->basemove_end - adjust->basemove_adjust)
		{
		  phdr[j].p_vaddr -= adj;
		  phdr[j].p_paddr -= adj;
		}
	      else
		phdr[j].p_offset += adj;
	    }
	  adjust->basemove_adjust += adj;
	  insert_readonly_section (ehdr, shdr, k, adjust);
	  shdr[k] = *add;
	  if (k == moveend)
	    {
	      addr = shdr[k - 1].sh_addr + shdr[k - 1].sh_size;
	      addr = (addr + add->sh_addralign - 1) & ~(add->sh_addralign - 1);
	    }
	  else
	    {
	      addr = (shdr[k + 1].sh_addr - add->sh_size)
		     & ~(add->sh_addralign - 1);
	    }

	  shdr[k].sh_addr = addr;
	  shdr[k].sh_offset = (addr - phdr[i].p_vaddr) + phdr[i].p_offset;
	  adjust_nonalloc (dso, ehdr, shdr, 0, 0, adj);
	  return k;
	}
    }

  /* We have to create new PT_LOAD if at all possible.  */
  addr = ehdr->e_phoff + (ehdr->e_phnum + 1) * ehdr->e_phentsize;
  for (j = 1; j < ehdr->e_shnum; ++j)
    {
      if (addr > shdr[j].sh_offset)
	{
	  GElf_Addr start, addstart, endaddr, *old_addr;
	  GElf_Addr minsize = ~(GElf_Addr) 0;
	  int movesec = -1, last, k, e;

	  if (ehdr->e_phoff < phdr[i].p_offset
	      || ehdr->e_phoff + (ehdr->e_phnum + 1) * ehdr->e_phentsize
		 > phdr[i].p_offset + phdr[i].p_filesz
	      || ! readonly_is_movable (dso, ehdr, shdr, j)
	      || shdr[j].sh_addr >= phdr[i].p_vaddr + phdr[i].p_filesz)
	    {
	      error (0, 0, "%s: No space in ELF segment table to add new ELF segment",
		     dso->filename);
	      return 0;
	    }

	  start = phdr[i].p_vaddr - phdr[i].p_offset + ehdr->e_phoff
		  + (ehdr->e_phnum + 1) * ehdr->e_phentsize;
	  for (last = 1; last < ehdr->e_shnum; ++last)
	    if (! readonly_is_movable (dso, ehdr, shdr, last)
		|| shdr[last].sh_addr >= phdr[i].p_vaddr + phdr[i].p_filesz)
	      break;
	  for (j = 1; j < last; ++j)
	    {
	      addstart = (start + add->sh_addralign - 1)
			 & ~(add->sh_addralign - 1);
	      start = (start + shdr[j].sh_addralign - 1)
		      & ~(shdr[j].sh_addralign - 1);
	      endaddr = -1;
	      if (j + 1 < ehdr->e_shnum)
		endaddr = shdr[j + 1].sh_addr;
	      if (phdr[i].p_vaddr + phdr[i].p_filesz < endaddr)
		endaddr = phdr[i].p_vaddr + phdr[i].p_filesz;

	      switch (shdr[j].sh_type)
		{
		case SHT_HASH:
		case SHT_GNU_HASH:
		case SHT_DYNSYM:
		case SHT_STRTAB:
		case SHT_GNU_verdef:
		case SHT_GNU_verneed:
		case SHT_GNU_versym:
		case SHT_GNU_LIBLIST:
		  if (endaddr >= start
		      && endaddr - start < minsize)
		    {
		      minsize = endaddr - start;
		      movesec = j;
		    }
		  if (endaddr > addstart
		      && endaddr - addstart > add->sh_size
		      && endaddr - addstart - add->sh_size
			 < minsize)
		    {
		      minsize = endaddr - addstart - add->sh_size;
		      movesec = j;
		    }
		  break;
		}

	      if (start + shdr[j].sh_size <= endaddr)
		{
		  movesec = j + 1;
		  break;
		}
	      start += shdr[j].sh_size;
	    }

	  if (movesec == -1)
	    {
	      error (0, 0, "%s: No space in ELF segment table to add new ELF segment",
		     dso->filename);
	      return 0;
	    }

	  start = phdr[i].p_vaddr - phdr[i].p_offset + ehdr->e_phoff
		  + (ehdr->e_phnum + 1) * ehdr->e_phentsize;
	  old_addr = (GElf_Addr *) alloca (movesec * sizeof (GElf_Addr));
	  for (k = 1; k < movesec; ++k)
	    {
	      start = (start + shdr[k].sh_addralign - 1)
		      & ~(shdr[k].sh_addralign - 1);
	      old_addr[k] = shdr[k].sh_addr;
	      shdr[k].sh_addr = start;
	      shdr[k].sh_offset = start + phdr[i].p_offset
				  - phdr[i].p_vaddr;
	      start += shdr[k].sh_size;
	    }

	  for (e = 0; e < ehdr->e_phnum; ++e)
	    if (phdr[e].p_type != PT_LOAD
		&& phdr[e].p_type != PT_GNU_STACK)
	      for (k = 1; k < movesec; ++k)
		if (old_addr[k] == phdr[e].p_vaddr)
		  {
		    if (phdr[e].p_filesz != shdr[k].sh_size
			|| phdr[e].p_memsz != shdr[k].sh_size)
		      {
			error (0, 0, "%s: Non-PT_LOAD segment spanning more than one section",
			       dso->filename);
			return 0;
		      }
		    phdr[e].p_vaddr += shdr[k].sh_addr - old_addr[k];
		    phdr[e].p_paddr += shdr[k].sh_addr - old_addr[k];
		    phdr[e].p_offset += shdr[k].sh_addr - old_addr[k];
		    break;
		  }

	  if (j < last)
	    /* Now continue as if there was place for a new PT_LOAD
	       in ElfW(Phdr) table initially.  */
	    break;
	  else
	    {
	      GElf_Shdr moveshdr;
	      int newidx, ret, movedidx, oldidx;

	      moveshdr = shdr[movesec];
	      newidx = remove_readonly_section (ehdr, shdr, movesec, adjust);
	      oldidx = adjust->move->new_to_old[movesec];
	      remove_section (adjust->move, movesec);
	      ret = find_readonly_space (dso, add, ehdr, phdr, shdr, adjust);
	      if (ret == 0)
		return 0;
	      movedidx = find_readonly_space (dso, &moveshdr, ehdr, phdr,
					      shdr, adjust);
	      if (movedidx == 0)
		return 0;
	      if (newidx != -1)
		adjust->new[newidx] = movedidx;
	      add_section (adjust->move, movedidx);
	      if (oldidx != -1)
		{
		  adjust->move->old_to_new[oldidx] = movedidx;
		  adjust->move->new_to_old[movedidx] = oldidx;
		}
	      if (movedidx <= ret)
		++ret;
	      return ret;
	    }
	}
    }

  for (i = 0, j = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD)
      j = i;
    else if (phdr[i].p_type == PT_PHDR)
      {
	if (phdr[i].p_filesz == ehdr->e_phnum * ehdr->e_phentsize)
	  phdr[i].p_filesz += ehdr->e_phentsize;
	if (phdr[i].p_memsz == ehdr->e_phnum * ehdr->e_phentsize)
	  phdr[i].p_memsz += ehdr->e_phentsize;
      }

  memmove (&phdr[j + 2], &phdr[j + 1],
	   (ehdr->e_phnum - j - 1) * sizeof (GElf_Phdr));
  ++ehdr->e_phnum;
  phdr[++j].p_type = PT_LOAD;
  phdr[j].p_offset = phdr[j - 1].p_offset + phdr[j - 1].p_filesz;
  phdr[j].p_offset = (phdr[j].p_offset + add->sh_addralign - 1)
		      & ~(add->sh_addralign - 1);
  phdr[j].p_align = phdr[j - 1].p_align;
  phdr[j].p_vaddr = phdr[j - 1].p_vaddr + phdr[j - 1].p_memsz;
  phdr[j].p_vaddr += (phdr[j].p_align - 1);
  phdr[j].p_vaddr &= ~(phdr[j].p_align - 1);
  phdr[j].p_vaddr += (phdr[j].p_offset & (phdr[j].p_align - 1));
  phdr[j].p_paddr = phdr[j].p_vaddr;
  /* Although the content of the segment is read-only, unless it ends on
     a page boundary, we must make it writeable. This is because the rest of
     the last page in the segment will be used as sbrk area which is assumed
     to be writeable.  */
  phdr[j].p_flags = (PF_R | PF_W);
  phdr[j].p_filesz = add->sh_size;
  phdr[j].p_memsz = add->sh_size;
  for (i = 1; i < ehdr->e_shnum; ++i)
    if (! (shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR)))
      break;
  assert (i < ehdr->e_shnum);
  insert_readonly_section (ehdr, shdr, i, adjust);
  shdr[i] = *add;
  shdr[i].sh_addr = phdr[j].p_vaddr;
  shdr[i].sh_offset = phdr[j].p_offset;
  adjust_nonalloc (dso, ehdr, shdr, 0, 0,
		   phdr[j].p_offset + phdr[j].p_filesz - phdr[j - 1].p_offset
		   - phdr[j - 1].p_filesz);
  return i;
}
