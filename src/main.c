/* Copyright (C) 2001, 2002, 2003, 2004, 2005 Red Hat, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <error.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>

#include "prelink.h"

#define PRELINK_CONF "/etc/prelink.conf"
#define PRELINK_CACHE "/etc/prelink.cache"

int all;
int force;
int verbose;
int print_cache;
int reloc_only;
GElf_Addr reloc_base;
int no_update;
int random_base;
int conserve_memory;
int libs_only;
int dry_run;
int dereference;
int one_file_system;
int enable_cxx_optimizations = 1;
int exec_shield;
int undo, verify;
enum verify_method_t verify_method;
int quick;
int compute_checksum;
long long seed;
GElf_Addr mmap_reg_start = ~(GElf_Addr) 0;
GElf_Addr mmap_reg_end = ~(GElf_Addr) 0;
const char *dynamic_linker;
const char *ld_library_path;
const char *prelink_conf = PRELINK_CONF;
const char *prelink_cache = PRELINK_CACHE;
const char *undo_output;

const char *argp_program_version = "prelink 1.0";

const char *argp_program_bug_address = "<jakub@redhat.com>";

static char argp_doc[] = "prelink -- program to relocate and prelink ELF shared libraries and programs";

#define OPT_DYNAMIC_LINKER	0x80
#define OPT_LD_LIBRARY_PATH	0x81
#define OPT_LIBS_ONLY		0x82
#define OPT_CXX_DISABLE		0x83
#define OPT_MMAP_REG_START	0x84
#define OPT_MMAP_REG_END	0x85
#define OPT_EXEC_SHIELD		0x86
#define OPT_NO_EXEC_SHIELD	0x87
#define OPT_SEED		0x88
#define OPT_MD5			0x89
#define OPT_SHA			0x8a
#define OPT_COMPUTE_CHECKSUM	0x8b

static struct argp_option options[] = {
  {"all",		'a', 0, 0,  "Prelink all binaries" },
  {"black-list",	'b', "PATH", 0, "Blacklist path" },
  {"cache-file",	'C', "CACHE", 0, "Use CACHE as cache file" },
  {"config-file",	'c', "CONF", 0, "Use CONF as configuration file" },
  {"force",		'f', 0, 0,  "Force prelinking" },
  {"dereference",	'h', 0, 0,  "Follow symlinks when processing directory trees from command line" },
  {"one-file-system",	'l', 0, 0,  "Stay in local file system when processing directories from command line" },
  {"conserve-memory",	'm', 0, 0,  "Allow libraries to overlap as long as they never appear in the same program" },
  {"no-update-cache",	'N', 0, 0,  "Don't update prelink cache" },
  {"dry-run",		'n', 0, 0,  "Don't actually prelink anything" },
  {"undo-output",	'o', "FILE", 0, "Undo output file" },
  {"print-cache",	'p', 0,	0,  "Print prelink cache" },
  {"quick",		'q', 0, 0,  "Quick scan" },
  {"random",		'R', 0, 0,  "Choose random base for libraries" },
  {"reloc-only",	'r', "BASE_ADDRESS", 0,  "Relocate library to given address, don't prelink" },
  {"undo",		'u', 0, 0,  "Undo prelink" },
  {"verbose",		'v', 0, 0,  "Produce verbose output" },
  {"verify",		'y', 0, 0,  "Verify file consistency by undoing and redoing prelink and printing original to standard output" },
  {"md5",		OPT_MD5, 0, 0, "For verify print MD5 sum of original to standard output instead of content" },
  {"sha",		OPT_SHA, 0, 0, "For verify print SHA sum of original to standard output instead of content" },
  {"dynamic-linker",	OPT_DYNAMIC_LINKER, "DYNAMIC_LINKER",
				0,  "Special dynamic linker path" },
  {"exec-shield",	OPT_EXEC_SHIELD, 0, 0, "Lay out libraries for exec-shield on IA-32" },
  {"no-exec-shield",	OPT_NO_EXEC_SHIELD, 0, 0, "Don't lay out libraries for exec-shield on IA-32" },
  {"ld-library-path",	OPT_LD_LIBRARY_PATH, "PATHLIST",
				0,  "What LD_LIBRARY_PATH should be used" },
  {"libs-only",		OPT_LIBS_ONLY, 0, 0, "Prelink only libraries, no binaries" },
  {"disable-c++-optimizations", OPT_CXX_DISABLE, 0, OPTION_HIDDEN, "" },
  {"mmap-region-start",	OPT_MMAP_REG_START, "BASE_ADDRESS", OPTION_HIDDEN, "" },
  {"mmap-region-end",	OPT_MMAP_REG_END, "BASE_ADDRESS", OPTION_HIDDEN, "" },
  {"seed",		OPT_SEED, "SEED", OPTION_HIDDEN, "" },
  {"compute-checksum",	OPT_COMPUTE_CHECKSUM, 0, OPTION_HIDDEN, "" },
  { 0 }
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  char *endarg;

  switch (key)
    {
    case 'a':
      all = 1;
      break;
    case 'b':
      if (add_to_blacklist (arg, dereference, one_file_system))
	exit (EXIT_FAILURE);
      break;
    case 'f':
      force = 1;
      break;
    case 'p':
      print_cache = 1;
      break;
    case 'q':
      quick = 1;
      break;
    case 'v':
      ++verbose;
      break;
    case 'R':
      random_base |= 1;
      break;
    case OPT_SEED:
      random_base |= 2;
      seed = strtoull (arg, &endarg, 0);
      if (endarg != strchr (arg, '\0'))
	error (EXIT_FAILURE, 0, "--seed option requires numberic argument");
      break;
    case 'r':
      reloc_only = 1;
      reloc_base = strtoull (arg, &endarg, 0);
      if (endarg != strchr (arg, '\0'))
	error (EXIT_FAILURE, 0, "-r option requires numberic argument");
      break;
    case 'h':
      dereference = 1;
      break;
    case 'l':
      one_file_system = 1;
      break;
    case 'm':
      conserve_memory = 1;
      break;
    case 'N':
      no_update = 1;
      break;
    case 'n':
      dry_run = 1;
      break;
    case 'C':
      prelink_cache = arg;
      break;
    case 'c':
      prelink_conf = arg;
      break;
    case 'u':
      undo = 1;
      break;
    case 'y':
      verify = 1;
      break;
    case 'o':
      undo_output = arg;
      break;
    case OPT_DYNAMIC_LINKER:
      dynamic_linker = arg;
      break;
    case OPT_LD_LIBRARY_PATH:
      ld_library_path = arg;
      break;
    case OPT_LIBS_ONLY:
      libs_only = 1;
      break;
    case OPT_MD5:
      verify_method = VERIFY_MD5;
      break;
    case OPT_SHA:
      verify_method = VERIFY_SHA;
      break;
    case OPT_CXX_DISABLE:
      enable_cxx_optimizations = 0;
      break;
    case OPT_MMAP_REG_START:
      mmap_reg_start = strtoull (arg, &endarg, 0);
      if (endarg != strchr (arg, '\0'))
	error (EXIT_FAILURE, 0, "--mmap-region-start option requires numberic argument");
      break;
    case OPT_MMAP_REG_END:
      mmap_reg_end = strtoull (arg, &endarg, 0);
      if (endarg != strchr (arg, '\0'))
	error (EXIT_FAILURE, 0, "--mmap-region-end option requires numberic argument");
      break;
    case OPT_EXEC_SHIELD:
      exec_shield = 1;
      break;
    case OPT_NO_EXEC_SHIELD:
      exec_shield = 0;
      break;
    case OPT_COMPUTE_CHECKSUM:
      compute_checksum = 1;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, "[FILES]", argp_doc };

int
main (int argc, char *argv[])
{
  int remaining, failures = 0;

  setlocale (LC_ALL, "");

  /* Set the default for exec_shield.  */
  if (! access ("/proc/sys/kernel/exec-shield", F_OK))
    exec_shield = 1;

  prelink_init_cache ();

  elf_version (EV_CURRENT);

  argp_parse (&argp, argc, argv, 0, &remaining, 0);

  if (ld_library_path == NULL)
    ld_library_path = getenv ("LD_LIBRARY_PATH");

  if (all && reloc_only)
    error (EXIT_FAILURE, 0, "--all and --reloc-only options are incompatible");
  if ((undo || verify) && reloc_only)
    error (EXIT_FAILURE, 0, "--undo and --reloc-only options are incompatible");
  if (verify && (undo || all))
    error (EXIT_FAILURE, 0, "--verify and either --undo or --all options are incompatible");
  if (dry_run && verify)
    error (EXIT_FAILURE, 0, "--dry-run and --verify options are incompatible");
  if ((undo || verify) && quick)
    error (EXIT_FAILURE, 0, "--undo and --quick options are incompatible");

  if (print_cache)
    {
      prelink_load_cache ();
      prelink_print_cache ();
      return 0;
    }

  if (remaining == argc && ! all)
    error (EXIT_FAILURE, 0, "no files given and --all not used");

  if (undo_output && (!undo || all))
    error (EXIT_FAILURE, 0, "-o can be only specified together with -u and without -a");

  if (undo_output && remaining + 1 != argc)
    error (EXIT_FAILURE, 0, "-o can only be used when undoing a single object");

  if (compute_checksum)
    {
      while (remaining < argc)
	{
	  DSO *dso = open_dso (argv[remaining++]);

	  if (dso == NULL || reopen_dso (dso, NULL, NULL)
	      || prelink_set_checksum (dso))
	    error (0, 0, "could not recompute checksum of %s", dso->filename);
	  close_dso (dso);
	  error (0, 0, "%08x %s\n", (unsigned int) dso->info_DT_CHECKSUM, dso->filename);
	}
      exit (0);
    }

  if (verify)
    {
      if (remaining + 1 != argc)
	error (EXIT_FAILURE, 0, "only one library or binary can be verified in a single command");
      return prelink_verify (argv[remaining]);
    }

  if (reloc_only || (undo && ! all))
    {
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
	      && (reloc_only || dso->ehdr.e_type != ET_EXEC))
	    {
	      ++failures;
	      error (0, 0, "%s is not a shared library", dso->filename);
	      continue;
	    }

	  if (undo)
	    ret = prelink_undo (dso);
	  else
	    ret = relocate_dso (dso, reloc_base);

	  if (ret)
	    {
	      ++failures;
	      close_dso (dso);
	      continue;
	    }

	  if (dynamic_info_is_set (dso, DT_CHECKSUM_BIT)
	      && dso_is_rdwr (dso)
	      && prelink_set_checksum (dso))
	    {
	      ++failures;
	      close_dso (dso);
	      continue;
	    }

	  if (dry_run)
	    {
	      close_dso (dso);
	      continue;
	    }

	  if (reloc_only)
	    dso->permissive = 1;
	  else if (undo_output)
	    {
	      const char *output = strdup (undo_output);
	      const char *orig_filename;
	      if (!output)
		{
		  ++failures;
		  close_dso (dso);
		  continue;
		}
	      if (dso->filename != dso->soname)
		orig_filename = dso->filename;
	      else
		orig_filename = strdup (dso->filename);
	      if (!orig_filename)
		{
		  ++failures;
		  close_dso (dso);
		  continue;
		}
	      dso->filename = output;
	      if (update_dso (dso, orig_filename))
		++failures;
	      free ((char *) orig_filename);
	      continue;
	    }

	  if (update_dso (dso, NULL))
	    ++failures;
	}

      return failures;
    }

  if (blacklist_from_config (prelink_conf))
    return EXIT_FAILURE;

  if (quick)
    prelink_load_cache ();

  if (gather_config (prelink_conf))
    return EXIT_FAILURE;

  while (remaining < argc)
    if (gather_object (argv[remaining++], dereference, one_file_system))
      return EXIT_FAILURE;

  if (gather_check_libs ())
    return EXIT_FAILURE;

  if (undo)
    return undo_all ();

  if (! all && ! quick)
    prelink_load_cache ();

  layout_libs ();
  prelink_all ();

  if (! no_update && ! dry_run)
    prelink_save_cache (all);
  return 0;
}
