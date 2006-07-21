/* Copyright (C) 2001, 2002, 2003, 2005 Red Hat, Inc.
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

int
find_reloc_sections (DSO *dso, struct reloc_info *rinfo)
{
  int first, last, rela, i;
  GElf_Addr start, end, pltstart, pltend;

  memset (rinfo, 0, sizeof (*rinfo));

  if (dynamic_info_is_set (dso, DT_REL)
      && dynamic_info_is_set (dso, DT_RELA))
    {
      error (0, 0, "%s: Cannot prelink object with both DT_REL and DT_RELA tags",
	     dso->filename);
      return 1;
    }

  rela = dynamic_info_is_set (dso, DT_RELA);

  if (rela)
    {
      start = dso->info[DT_RELA];
      end = dso->info[DT_RELA] + dso->info[DT_RELASZ];
    }
  else
    {
      start = dso->info[DT_REL];
      end = dso->info[DT_REL] + dso->info[DT_RELSZ];
    }
  rinfo->reldyn_rela = rela;

  if (dso->info[DT_JMPREL])
    {
      pltstart = dso->info[DT_JMPREL];
      pltend = dso->info[DT_JMPREL] + dso->info[DT_PLTRELSZ];
      first = addr_to_sec (dso, pltstart);
      last = addr_to_sec (dso, pltend - 1);
      if (first == -1
	  || last == -1
	  || first != last
	  || dso->shdr[first].sh_addr != pltstart
	  || dso->shdr[first].sh_addr + dso->shdr[first].sh_size != pltend
	  || (dso->info[DT_PLTREL] != DT_REL
	      && dso->info[DT_PLTREL] != DT_RELA)
	  || dso->shdr[first].sh_type
	     != (dso->info[DT_PLTREL] == DT_RELA ? SHT_RELA : SHT_REL)
	  || strcmp (strptr (dso, dso->ehdr.e_shstrndx,
			     dso->shdr[first].sh_name),
		     dso->info[DT_PLTREL] == DT_RELA
		     ? ".rela.plt" : ".rel.plt"))
	{
	  error (0, 0, "%s: DT_JMPREL tags don't surround .rel%s.plt section",
		 dso->filename, dso->info[DT_PLTREL] == DT_RELA ? "a" : "");
	  return 1;
	}
      rinfo->plt = first;
      rinfo->plt_rela = (dso->shdr[first].sh_type == SHT_RELA);
      if (dso->shdr[first].sh_type == SHT_REL
	  && dso->arch->need_rel_to_rela != NULL
	  && dso->arch->need_rel_to_rela (dso, first, first))
	rinfo->rel_to_rela_plt = 1;
    }
  else
    {
      pltstart = end;
      pltend = end;
    }

  if (start == 0 && end == 0)
    {
      /* No non-PLT relocations.  */
      return 0;
    }

  if (start == end)
    {
      first = 0;
      last = 0;
    }
  else
    {
      first = addr_to_sec (dso, start);
      last = addr_to_sec (dso, end - 1);

      if (first == -1
	  || last == -1
	  || dso->shdr[first].sh_addr != start
	  || dso->shdr[last].sh_addr + dso->shdr[last].sh_size != end)
	{
	  error (0, 0, "%s: DT_REL%s tags don't surround whole relocation sections",
		 dso->filename, rela ? "A" : "");
	  return 1;
	}

      for (i = first; i <= last; i++)
	if (dso->shdr[i].sh_type != (rela ? SHT_RELA : SHT_REL))
	  {
	    error (0, 0, "%s: DT_REL%s tags don't surround relocation sections of expected type",
		   dso->filename, rela ? "A" : "");
	    return 1;
	  }
    }

  if (pltstart != end && pltend != end)
    {
      error (0, 0, "%s: DT_JMPREL tag not adjacent to DT_REL%s relocations",
	     dso->filename, rela ? "A" : "");
      return 1;
    }

  if (pltstart == start && pltend == end)
    {
      /* No non-PLT relocations.  */
      rinfo->overlap = 1;
      return 0;
    }

  if (pltstart != end && pltend == end)
    {
      rinfo->overlap = 1;
      --last;
    }

  rinfo->first = first;
  rinfo->last = last;
  if (! rela
      && first
      && dso->arch->need_rel_to_rela != NULL
      && dso->arch->need_rel_to_rela (dso, first, last))
    rinfo->rel_to_rela = 1;
  return 0;
}

int
convert_rel_to_rela (DSO *dso, int i)
{
  Elf_Data d1, d2, *d;
  Elf_Scn *scn;
  GElf_Rel rel;
  GElf_Rela rela;
  int ndx, maxndx;

  scn = dso->scn[i];
  d = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, d) == NULL);
  assert (d->d_off == 0);
  assert (d->d_size == dso->shdr[i].sh_size);
  d1 = *d;
  d2 = *d;
  assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
  assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
  d1.d_size = d->d_size / 2 * 3;
  d1.d_buf = malloc (d1.d_size);
  d1.d_type = ELF_T_RELA;
  if (d1.d_buf == NULL)
    {
      error (0, ENOMEM, "Cannot convert REL section to RELA");
      return 1;
    }

  maxndx = d->d_size / dso->shdr[i].sh_entsize;
  for (ndx = 0; ndx < maxndx; ndx++)
    {
      if (gelfx_getrel (dso->elf, d, ndx, &rel) == 0
	  || dso->arch->rel_to_rela (dso, &rel, &rela))
	{
	  free (d1.d_buf);
	  return 1;
	}
      /* gelf_update_rel etc. should have Elf * argument, so that
	 we don't have to do this crap.  */
      *d = d1;
      if (gelfx_update_rela (dso->elf, d, ndx, &rela) == 0)
	{
	  *d = d2;
	  free (d1.d_buf);
	  return 1;
	}
      *d = d2;
    }

  free (d2.d_buf);
  *d = d1;
  dso->shdr[i].sh_entsize
    = gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
  dso->shdr[i].sh_type = SHT_RELA;
  return 0;
}

int
convert_rela_to_rel (DSO *dso, int i)
{
  Elf_Data d1, d2, *d;
  Elf_Scn *scn;
  GElf_Rel rel;
  GElf_Rela rela;
  int ndx, maxndx;

  scn = dso->scn[i];
  d = elf_getdata (scn, NULL);
  assert (elf_getdata (scn, d) == NULL);
  assert (d->d_off == 0);
  assert (d->d_size == dso->shdr[i].sh_size);
  d1 = *d;
  d2 = *d;
  assert (sizeof (Elf32_Rel) * 3 == sizeof (Elf32_Rela) * 2);
  assert (sizeof (Elf64_Rel) * 3 == sizeof (Elf64_Rela) * 2);
  d1.d_size = d->d_size / 3 * 2;
  d1.d_buf = malloc (d1.d_size);
  d1.d_type = ELF_T_REL;
  if (d1.d_buf == NULL)
    {
      error (0, ENOMEM, "Cannot convert RELA section to REL");
      return 1;
    }

  maxndx = d->d_size / dso->shdr[i].sh_entsize;
  for (ndx = 0; ndx < maxndx; ndx++)
    {
      if (gelfx_getrela (dso->elf, d, ndx, &rela) == 0
	  || dso->arch->rela_to_rel (dso, &rela, &rel))
	{
	  free (d1.d_buf);
	  return 1;
	}
      /* gelf_update_rela etc. should have Elf * argument, so that
	 we don't have to do this crap.  */
      *d = d1;
      if (gelfx_update_rel (dso->elf, d, ndx, &rel) == 0)
	{
	  *d = d2;
	  free (d1.d_buf);
	  return 1;
	}
      *d = d2;
    }

  free (d2.d_buf);
  *d = d1;
  dso->shdr[i].sh_entsize
    = gelf_fsize (dso->elf, ELF_T_REL, 1, EV_CURRENT);
  dso->shdr[i].sh_type = SHT_REL;
  return 0;
}

int
update_dynamic_rel (DSO *dso, struct reloc_info *rinfo)
{
  GElf_Dyn *info[DT_NUM], *info_DT_RELCOUNT, *info_DT_RELACOUNT;
  GElf_Dyn *dynamic = NULL;
  int rel = rinfo->first, plt = rinfo->plt, overlap = rinfo->overlap;
  int dynsec, count = 0, loc;
  Elf_Data *data;
  Elf_Scn *scn = NULL;

  memset (&info, 0, sizeof (info));
  info_DT_RELCOUNT = NULL;
  info_DT_RELACOUNT = NULL;
  for (dynsec = 0; dynsec < dso->ehdr.e_shnum; dynsec++)
    if (dso->shdr[dynsec].sh_type == SHT_DYNAMIC)
      {
	scn = dso->scn[dynsec];
	dynamic = alloca (dso->shdr[dynsec].sh_size
			  / dso->shdr[dynsec].sh_entsize * sizeof (GElf_Dyn));
	loc = 0;
	data = NULL;
	while ((data = elf_getdata (scn, data)) != NULL)
	  {
	    int ndx, maxndx;

	    maxndx = data->d_size / dso->shdr[dynsec].sh_entsize;
	    for (ndx = 0; ndx < maxndx; ++ndx, ++loc)
	      {
		gelfx_getdyn (dso->elf, data, ndx, dynamic + loc);
		if (dynamic[loc].d_tag == DT_NULL)
		  break;
		else if ((GElf_Xword) dynamic[loc].d_tag < DT_NUM)
		  info[dynamic[loc].d_tag] = dynamic + loc;
		else if (dynamic[loc].d_tag == DT_RELCOUNT)
		  info_DT_RELCOUNT = dynamic + loc;
		else if (dynamic[loc].d_tag == DT_RELACOUNT)
		  info_DT_RELACOUNT = dynamic + loc;
	      }
	    if (ndx < maxndx)
	      break;
	  }
	count = loc;
	break;
      }

  if (rel && plt && overlap)
    {
      if (dso->shdr[rel].sh_type != dso->shdr[plt].sh_type)
	overlap = 0;
    }

  if (rel || (plt && overlap))
    {
      int dt_RELENT, dt_REL, dt_RELSZ;

      if (rinfo->reldyn_rela)
	{
	  dt_RELENT = DT_RELAENT;
	  dt_REL = DT_RELA;
	  dt_RELSZ = DT_RELASZ;
	}
      else
	{
	  dt_RELENT = DT_RELENT;
	  dt_REL = DT_REL;
	  dt_RELSZ = DT_RELSZ;
	}

      assert (dso->info[dt_RELENT]
	      == gelf_fsize (dso->elf, rinfo->reldyn_rela
			     ? ELF_T_RELA : ELF_T_REL, 1, EV_CURRENT));
      assert (dso->info[dt_REL] != 0);
      assert (dso->info[dt_RELSZ] != 0);

      info[dt_REL]->d_un.d_ptr = dso->shdr[rel ?: plt].sh_addr;
      if (plt && overlap)
	info[dt_RELSZ]->d_un.d_val =
	  dso->shdr[plt].sh_addr + dso->shdr[plt].sh_size;
      else
	info[dt_RELSZ]->d_un.d_val =
	  dso->shdr[rinfo->last].sh_addr + dso->shdr[rinfo->last].sh_size;
      info[dt_RELSZ]->d_un.d_val -= info[dt_REL]->d_un.d_ptr;

      if (!rinfo->reldyn_rela && dso->shdr[rel ?: plt].sh_type == SHT_RELA)
	{
	  info[DT_RELENT]->d_un.d_val =
	    gelf_fsize (dso->elf, ELF_T_RELA, 1, EV_CURRENT);
	  info[DT_REL]->d_tag = DT_RELA;
	  info[DT_RELSZ]->d_tag = DT_RELASZ;
	  info[DT_RELENT]->d_tag = DT_RELAENT;
	  if (info_DT_RELCOUNT)
	    info_DT_RELCOUNT->d_tag = DT_RELACOUNT;
	}
      else if (rinfo->reldyn_rela && dso->shdr[rel ?: plt].sh_type == SHT_REL)
	{
	  info[DT_RELAENT]->d_un.d_val =
	    gelf_fsize (dso->elf, ELF_T_REL, 1, EV_CURRENT);
	  info[DT_RELA]->d_tag = DT_REL;
	  info[DT_RELASZ]->d_tag = DT_RELSZ;
	  info[DT_RELAENT]->d_tag = DT_RELENT;
	  if (info_DT_RELACOUNT)
	    info_DT_RELACOUNT->d_tag = DT_RELCOUNT;
	}
    }

  if (plt)
    {
      assert (dso->info[DT_JMPREL] != 0);
      assert (dso->info[DT_PLTREL] == rinfo->plt_rela ? DT_RELA : DT_REL);

      info[DT_JMPREL]->d_un.d_ptr = dso->shdr[plt].sh_addr;
      if (!rinfo->plt_rela && dso->shdr[plt].sh_type == SHT_RELA)
	{
	  info[DT_PLTREL]->d_un.d_val = DT_RELA;
	  info[DT_PLTRELSZ]->d_un.d_val = dso->shdr[plt].sh_size;
	}
      else if (rinfo->plt_rela && dso->shdr[plt].sh_type == SHT_REL)
	{
	  info[DT_PLTREL]->d_un.d_val = DT_REL;
	  info[DT_PLTRELSZ]->d_un.d_val = dso->shdr[plt].sh_size;
	}

      if (!rel && !overlap)
	{
	  int dt_REL = rinfo->reldyn_rela ? DT_RELA : DT_REL;

	  if (info[dt_REL] && info[dt_REL]->d_un.d_ptr)
	    info[dt_REL]->d_un.d_ptr = info[DT_JMPREL]->d_un.d_ptr;
	}
    }

  loc = 0;
  data = NULL;
  while ((data = elf_getdata (scn, data)) != NULL)
    {
      int ndx, maxndx;

      maxndx = data->d_size / dso->shdr[dynsec].sh_entsize;
      for (ndx = 0; ndx < maxndx && loc < count; ++ndx, ++loc)
	if ((GElf_Xword) dynamic[loc].d_tag < DT_NUM
	    || dynamic[loc].d_tag == DT_RELCOUNT
	    || dynamic[loc].d_tag == DT_RELACOUNT)
	  gelfx_update_dyn (dso->elf, data, ndx, dynamic + loc);
      if (ndx < maxndx)
	break;
    }

  read_dynamic (dso);
  return 0;
}
