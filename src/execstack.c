/* Copyright (C) 2003, 2005, 2010 Red Hat, Inc.
   Written by Jakub Jelinek <jakub@redhat.com>, 2003.

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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "prelink.h"

int set;
int execflag;

const char *argp_program_version = "execstack 1.0";

const char *argp_program_bug_address = "<jakub@redhat.com>";

static char argp_doc[] = "execstack -- program to query or set executable stack flag";

static struct argp_option options[] = {
  {"set-execstack",	's', 0, 0,  "Set executable stack flag bit" },
  {"execstack",		's', 0, OPTION_HIDDEN, "" },
  {"clear-execstack",	'c', 0, 0,  "Clear executable stack flag bit" },
  {"noexecstack",	'c', 0, OPTION_HIDDEN, "" },
  {"query",		'q', 0, 0,  "Query executable stack flag bit" },
  { 0 }
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 's':
      set = 1;
      execflag = 1;
      break;
    case 'c':
      set = 1;
      execflag = 0;
      break;
    case 'q':
      set = 0;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, 0, argp_doc };

static int execstack_set (DSO *dso, int flag);

static void
execstack_fill_phdr (DSO *dso, int i, int flag)
{
  memset (&dso->phdr[i], 0, sizeof (dso->phdr[i]));
  dso->phdr[i].p_type = PT_GNU_STACK;
  dso->phdr[i].p_flags = PF_W | PF_R | (flag ? PF_X : 0);
  dso->phdr[i].p_align = gelf_fsize (dso->elf, ELF_T_ADDR, 1, EV_CURRENT);
}

static int
execstack_make_rdwr (DSO *dso, int flag)
{
  int i, fd = -1, status;
  pid_t pid;
  DSO *ndso = NULL;
  char *p = NULL;
  char filename[strlen (dso->filename) + sizeof ".#execstack#.XXXXXX"];

  for (i = 0; i < dso->ehdr.e_shnum; ++i)
    {
      const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				 dso->shdr[i].sh_name);
      if (strcmp (name, ".gnu.prelink_undo") == 0)
	break;
    }

  if (i == dso->ehdr.e_shnum)
    return reopen_dso (dso, NULL, NULL) ? 1 : -1;

  /* We need to unprelink the file first, so that prelink --undo
     or reprelinking it doesn't destroy the PT_GNU_STACK segment
     header we've created.  */
  sprintf (filename, "%s.#execstack#.XXXXXX", dso->filename);

  fd = mkstemp (filename);
  if (fd == -1)
    {
      error (0, 0, "%s: Cannot create temporary file",
	     dso->filename);
      goto error_out;
    }

  p = strdup (dso->filename);
  if (p == NULL)
    {
      error (0, ENOMEM, "%s: Cannot create temporary file",
	     dso->filename);
      goto error_out;
    }

  pid = vfork ();
  if (pid == 0)
    {
      close (fd);
      execlp ("prelink", "prelink", "-u", "-o", filename,
	      dso->filename, NULL);
      execl (SBINDIR "/prelink", "prelink", "-u", "-o", filename,
	     dso->filename, NULL);
      _exit (-1);
    }

  if (pid < 0)
    {
      error (0, errno, "%s: Cannot run prelink --undo",
	     dso->filename);
      goto error_out;
    }

  if (waitpid (pid, &status, 0) < 0
      || !WIFEXITED (status)
      || WEXITSTATUS (status))
    {
      error (0, 0, "%s: prelink --undo failed", dso->filename);
      goto error_out;
    }

  ndso = open_dso (filename);
  if (ndso == NULL)
    {
      error (0, 0, "%s: Couldn't open prelink --undo output",
	     dso->filename);
      goto error_out;
    }

  for (i = 0; i < ndso->ehdr.e_shnum; ++i)
    {
      const char *name = strptr (ndso, ndso->ehdr.e_shstrndx,
				 ndso->shdr[i].sh_name);
      if (strcmp (name, ".gnu.prelink_undo") == 0)
	break;
    }

  if (i != ndso->ehdr.e_shnum)
    {
      error (0, 0, "%s: prelink --undo output contains .gnu.prelink_undo section",
	     dso->filename);
      goto error_out;
    }

  if (ndso->ehdr.e_type != dso->ehdr.e_type)
    {
      error (0, 0, "%s: Object type changed during prelink --undo operation",
	     dso->filename);
    }

  if (ndso->filename != ndso->soname)
    free ((char *) ndso->filename);
  ndso->filename = p;
  p = NULL;

  unlink (filename);
  close (fd);
  fd = -1;
  close_dso (dso);
  return execstack_set (ndso, flag);

error_out:
  free (p);
  if (ndso != NULL)
    close_dso (ndso);
  if (fd != -1)
    {
      unlink (filename);
      close (fd);
    }
  close_dso (dso);
  return 1;
}

static int
execstack_set (DSO *dso, int flag)
{
  int i, null = -1, last, ret;
  GElf_Addr lowoff = ~(GElf_Addr) 0, start = 0, align = 0;
  GElf_Addr adjust;

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_GNU_STACK)
      {
	/* Found PT_GNU_STACK.  Check if we need any change or not.  */
	if (flag ^ ((dso->phdr[i].p_flags & PF_X) != 0))
	  {
	    ret = execstack_make_rdwr (dso, flag);
	    if (ret != -1)
	      return ret;
	    dso->phdr[i].p_flags ^= PF_X;
	    goto out_write;
	  }
	else
	  goto out_close;
      }
    else if (dso->phdr[i].p_type == PT_NULL)
      null = i;

  if (null != -1)
    {
      /* Overwrite PT_NULL segment with PT_GNU_STACK.  */
      ret = execstack_make_rdwr (dso, flag);
      if (ret != -1)
	return ret;
      execstack_fill_phdr (dso, i, flag);
      goto out_write;
    }

  if (dso->ehdr.e_shnum == 0)
    {
      error (0, 0, "%s: Section header table missing", dso->filename);
      goto error_out;
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      if (lowoff > dso->shdr[i].sh_offset)
	{
	  if (dso->shdr[i].sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR))
	    {
	      lowoff = dso->shdr[i].sh_offset;
	      start = dso->shdr[i].sh_addr;
	    }
	  else
	    {
	      error (0, 0, "%s: Non-alloced sections before alloced ones",
		     dso->filename);
	      goto error_out;
	    }
	}

      if (dso->shdr[i].sh_addralign > align)
	align = dso->shdr[i].sh_addralign;
    }

  if (dso->ehdr.e_phoff >= lowoff)
    {
      error (0, 0, "%s: Program header table not before all sections",
	     dso->filename);
      goto error_out;
    }

  if (dso->ehdr.e_shoff <= lowoff)
    {
      error (0, 0, "%s: Section header table before first section",
	     dso->filename);
      goto error_out;
    }

  if (dso->ehdr.e_phoff + (dso->ehdr.e_phnum + 1) * dso->ehdr.e_phentsize
      <= lowoff)
    {
      /* There is enough space for the headers even without reshuffling
	 anything.  */
      for (i = 0; i < dso->ehdr.e_phnum; ++i)
	if (dso->phdr[i].p_type == PT_PHDR)
	  {
	    if (dso->phdr[i].p_filesz
		== dso->ehdr.e_phnum * dso->ehdr.e_phentsize)
	      dso->phdr[i].p_filesz += dso->ehdr.e_phentsize;
	    if (dso->phdr[i].p_memsz
		== dso->ehdr.e_phnum * dso->ehdr.e_phentsize)
	      dso->phdr[i].p_memsz += dso->ehdr.e_phentsize;
	  }
      i = dso->ehdr.e_phnum++;
      ret = execstack_make_rdwr (dso, flag);
      if (ret != -1)
	return ret;
      execstack_fill_phdr (dso, i, flag);
      goto out_write;
    }

  if (dso->ehdr.e_type != ET_DYN)
    {
      error (0, 0, "%s: Reshuffling of objects to make room for\n"
		   "program header entry only supported for shared libraries",
	     dso->filename);
      goto error_out;
    }

  adjust = dso->ehdr.e_phoff + (dso->ehdr.e_phnum + 1) * dso->ehdr.e_phentsize
	   - lowoff;
  if (align)
    adjust = (adjust + align - 1) & ~(align - 1);

  /* Need to make sure adjust doesn't cause different Phdr segments
     to overlap on the same page.  */
  last = -1;
  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_LOAD
	&& dso->phdr[i].p_vaddr + dso->phdr[i].p_memsz >= start)
      {
	if (last != -1
	    && (((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz - 1)
		 ^ dso->phdr[i].p_vaddr)
		& ~(dso->arch->max_page_size - 1))
	    && !(((dso->phdr[last].p_vaddr + dso->phdr[last].p_memsz
		   + adjust - 1)
		  ^ (dso->phdr[i].p_vaddr + adjust))
		 & ~(dso->arch->max_page_size - 1)))
	  {
	    if (align >= dso->arch->max_page_size)
	      {
		error (0, 0, "%s: Cannot grow reloc sections", dso->filename);
		goto error_out;
	      }
	    adjust = (adjust + dso->arch->max_page_size - 1)
		     & ~(dso->arch->max_page_size - 1);
	  }
	last = i;
      }

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_PHDR)
      {
	if (dso->phdr[i].p_filesz == dso->ehdr.e_phnum * dso->ehdr.e_phentsize)
	  dso->phdr[i].p_filesz += dso->ehdr.e_phentsize;
	if (dso->phdr[i].p_memsz == dso->ehdr.e_phnum * dso->ehdr.e_phentsize)
	  dso->phdr[i].p_memsz += dso->ehdr.e_phentsize;
      }

  i = dso->ehdr.e_phnum++;
  ret = execstack_make_rdwr (dso, flag);
  if (ret != -1)
    return ret;

  if (adjust_dso (dso, start, adjust))
    goto error_out;

  execstack_fill_phdr (dso, i, flag);

out_write:
  if (dynamic_info_is_set (dso, DT_CHECKSUM_BIT)
      && dso_is_rdwr (dso)
      && prelink_set_checksum (dso))
    goto error_out;

  dso->permissive = 1;

  return update_dso (dso, NULL);

out_close:
  close_dso (dso);
  return 0;

error_out:
  close_dso (dso);
  return 1;
}

static int
execstack_query (DSO *dso)
{
  int stack = '?', i;

  for (i = 0; i < dso->ehdr.e_phnum; ++i)
    if (dso->phdr[i].p_type == PT_GNU_STACK)
      {
	stack = (dso->phdr[i].p_flags & PF_X) ? 'X' : '-';
	break;
      }
  printf ("%c %s\n", stack, dso->filename);
  close_dso (dso);
  return 0;
}

int
main (int argc, char *argv[])
{
  int remaining, failures = 0;

  setlocale (LC_ALL, "");

  argp_parse (&argp, argc, argv, 0, &remaining, 0);

  elf_version (EV_CURRENT);

  if (remaining == argc)
    error (EXIT_FAILURE, 0, "no files given");

  while (remaining < argc)
    {
      DSO *dso = open_dso (argv[remaining++]);
      int ret;

      if (dso == NULL)
	{
	  ++failures;
	  continue;
	}

      if (dso->ehdr.e_type != ET_DYN
	  && dso->ehdr.e_type != ET_EXEC)
	{
	  ++failures;
	  error (0, 0, "%s is not a shared library nor executable", dso->filename);
	  continue;
	}

      if (set)
	ret = execstack_set (dso, execflag);
      else
	ret = execstack_query (dso);

      if (ret)
	++failures;
    }

  return failures;
}

/* FIXME: Dummy.  When arch dependent files are split into adjust and prelink
   parts, this can go away.  */
struct prelink_conflict *
prelink_conflict (struct prelink_info *info, GElf_Word r_sym, int reloc_type)
{
  abort ();
}

GElf_Rela *
prelink_conflict_add_rela (struct prelink_info *info)
{
  abort ();
}

ssize_t
send_file (int outfd, int infd, off_t *poff, size_t count)
{
  abort ();
}

GElf_Addr mmap_reg_start;
GElf_Addr mmap_reg_end;
int exec_shield;
