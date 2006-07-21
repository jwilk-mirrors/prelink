/* Copyright (C) 2002, 2003 Red Hat, Inc.
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
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include "prelink.h"
#include "md5.h"
#include "sha.h"

static ssize_t
send_file (int outfd, int infd, off_t *poff, size_t count)
{
  char buf[65536], *b, *p, *q;
  size_t todo = count, len;
  ssize_t n;

  b = mmap (NULL, count, PROT_READ, MAP_PRIVATE, infd, *poff);
  if (b != MAP_FAILED)
    {
      p = b;
      q = p + count;
      while (p != q)
	{
	  n = TEMP_FAILURE_RETRY (write (outfd, p, q - p));
	  if (n < 0)
	    {
	      munmap (b, count);
	      return -1;
	    }
	  p += n;
	}
      munmap (b, count);
      return count;
    }

  if (lseek (infd, *poff, SEEK_SET) != *poff)
    return -1;
  while (todo > 0)
    {
      len = todo > sizeof (buf) ? sizeof (buf) : todo;
      p = buf;
      q = buf + len;
      while (p != q)
	{
	  n = TEMP_FAILURE_RETRY (read (infd, p, q - p));
	  if (n < 0)
	    return -1;
	  p += n;
	}
      p = buf;
      while (p != q)
	{
	  n = TEMP_FAILURE_RETRY (write (outfd, p, q - p));
	  if (n < 0)
	    return -1;
	  p += n;
	}
      todo -= len;
    }
  return count;
}

static int
checksum_file (int fd, size_t count,
	       void (*sum) (const void *, size_t, void *), void *arg)
{
  char buf[65536+64], *b, *p, *q;
  size_t todo = count, len;
  ssize_t n;

  b = mmap (NULL, count, PROT_READ, MAP_PRIVATE, fd, 0);
  if (b != MAP_FAILED)
    {
      sum (b, count, arg);
      munmap (b, count);
      return 0;
    }

  b = (char *) (((uintptr_t) buf + 63) & ~(uintptr_t) 63);
  while (todo > 0)
    {
      len = todo > 65536 ? 65536 : todo;
      p = b;
      q = b + len;
      while (p != q)
	{
	  n = TEMP_FAILURE_RETRY (read (fd, p, q - p));
	  if (n < 0)
	    return 1;
	  p += n;
	}
      sum (b, len, arg);
      todo -= len;
    }
  return 0;
}

static int
handle_verify (int fd, const char *filename)
{
  off_t off;
  size_t cnt;
  struct stat64 st;

  if (fstat64 (fd, &st) < 0)
    {
      error (0, errno, "%s: couldn't fstat temporary file", filename);
      return 1;
    }

  if (verify_method == VERIFY_CONTENT)
    {
      off = 0;
      if (send_file (1, fd, &off, st.st_size) != st.st_size)
	{
	  error (0, errno, "Couldn't write file to standard output");
	  return 1;
	}
    }
  else if (verify_method == VERIFY_MD5)
    {
      struct md5_ctx ctx;
      unsigned char bin_buffer[16];

      md5_init_ctx (&ctx);
      if (checksum_file (fd, st.st_size,
			 (void (*) (const void *, size_t, void *))
			 md5_process_bytes, &ctx))
	{
	  error (0, errno, "%s: Couldn't read temporary file", filename);
	  return 1;
	}

      md5_finish_ctx (&ctx, bin_buffer);
      for (cnt = 0; cnt < 16; ++cnt)
	printf ("%02x", bin_buffer[cnt]);
      printf ("  %s\n", filename);
    }
  else if (verify_method == VERIFY_SHA)
    {
      struct sha_ctx ctx;
      unsigned char bin_buffer[20];

      sha_init_ctx (&ctx);
      if (checksum_file (fd, st.st_size,
			 (void (*) (const void *, size_t, void *))
			 sha_process_bytes, &ctx))
	{
	  error (0, errno, "%s: Couldn't read temporary file", filename);
	  return 1;
	}

      sha_finish_ctx (&ctx, bin_buffer);
      for (cnt = 0; cnt < 20; ++cnt)
	printf ("%02x", bin_buffer[cnt]);
      printf ("  %s\n", filename);
    }
  return 0;
}

int
prelink_verify (const char *filename)
{
  DSO *dso = NULL, *dso2 = NULL;
  int fd = -1, fdorig = -1, fdundone = -1, undo, ret;
  struct stat64 st, st2;
  struct prelink_entry *ent;
  GElf_Addr base;
  char buffer[32768], buffer2[32768];
  size_t count;
  char *p, *q;

  if (stat64 (filename, &st) < 0)
    error (EXIT_FAILURE, errno, "Couldn't stat %s", filename);

  dso = open_dso (filename);
  if (dso == NULL)
    goto not_prelinked;

  if (dso->ehdr.e_type != ET_DYN && dso->ehdr.e_type != ET_EXEC)
    {
      error (0, 0, "%s is not an ELF shared library nor binary", filename);
      goto not_prelinked;
    }

  for (undo = 1; undo < dso->ehdr.e_shnum; ++undo)
    if (! strcmp (strptr (dso, dso->ehdr.e_shstrndx, dso->shdr[undo].sh_name),
		  ".gnu.prelink_undo"))
      break;

  if (undo == dso->ehdr.e_shnum)
    goto not_prelinked;

  if (fstat64 (dso->fd, &st2) < 0)
    {
      error (0, errno, "Couldn't fstat %s", filename);
      goto failure;
    }

  if (st.st_dev != st2.st_dev || st.st_ino != st2.st_ino
      || st.st_size != st2.st_size)
    {
      error (0, 0, "%s: changed during --verify", filename);
      goto failure;
    }

  if (gather_config (prelink_conf))
    goto failure;

  if (gather_object (filename, 0, 0))
    goto failure;

  ent = prelink_find_entry (filename, &st, 0);
  if (ent == NULL)
    {
      error (0, 0, "%s disappeared while running --verify", filename);
      goto failure;
    }

  if (ent->done != 2)
    {
      error (0, 0, "%s: at least one of file's dependencies has changed since prelinking",
	     filename);
      goto failure;
    }

  base = dso->base;
  ent->base = base;

  ret = prelink_undo (dso);
  if (ret)
    goto failure;

  switch (write_dso (dso))
    {
    case 2:
      error (0, 0, "Could not write temporary for %s: %s", filename,
	     elf_errmsg (-1));
      goto failure;
    case 1:
      goto failure;
    case 0:
      break;
    }

  fd = open (dso->temp_filename, O_RDONLY);
  if (fd < 0)
    {
      error (0, errno, "Could not verify %s", filename);
      goto failure;
    }

  fdorig = dup (dso->fdro);
  if (fdorig < 0)
    {
      error (0, errno, "Could not verify %s", filename);
      goto failure;
    }

  ent->filename = dso->temp_filename;
  dso->temp_filename = NULL;
  close_dso (dso);
  dso = NULL;

  fchmod (fd, 0700);

  dso2 = fdopen_dso (fd, filename);
  if (dso2 == NULL)
    goto failure;
  fd = -1;

  if (prelink_prepare (dso2))
    goto failure;

  if (ent->type == ET_DYN && relocate_dso (dso2, base))
    goto failure;

  if (prelink (dso2, ent))
    goto failure;

  unlink (ent->filename);

  if (write_dso (dso2))
    goto failure;

  fd = dup (dso2->fd);
  if (fd < 0)
    {
      error (0, errno, "Could not verify %s", filename);
      goto failure;
    }

  fdundone = dup (dso2->fdro);
  if (fdundone < 0)
    {
      error (0, errno, "Could not verify %s", filename);
      goto failure;
    }

  close_dso (dso2);
  dso2 = NULL;

  if (fstat64 (fdorig, &st2) < 0)
    {
      error (0, errno, "Couldn't fstat %s", filename);
      goto failure;
    }

  if (st.st_dev != st2.st_dev || st.st_ino != st2.st_ino
      || st.st_size != st2.st_size)
    {
      error (0, 0, "%s: changed during --verify", filename);
      goto failure;
    }

  if (fstat64 (fd, &st2) < 0)
    {
      error (0, errno, "Couldn't fstat temporary file");
      goto failure;
    }

  if (st.st_size != st2.st_size)
    {
      error (0, 0, "%s: prelinked file size differs", filename);
      goto failure;
    }

  q = MAP_FAILED;
  p = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fdorig, 0);
  if (p != MAP_FAILED)
    {
      q = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (q == MAP_FAILED)
	{
	  munmap (p, st.st_size);
	  p = MAP_FAILED;
	}
    }
  if (p != MAP_FAILED)
    {
      int ret = memcmp (p, q, st.st_size);

      munmap (p, st.st_size);
      munmap (q, st.st_size);
      if (ret != 0)
	{
	  error (0, 0, "%s: prelinked file was modified", filename);
	  goto failure;
	}
    }
  else
    {
      if (lseek (fdorig, 0, SEEK_SET) != 0
	  || lseek (fd, 0, SEEK_SET) != 0)
	{
	  error (0, errno, "%s: couldn't seek to start of files", filename);
	  goto failure;
	}

      count = st.st_size;
      while (count > 0)
	{
	  size_t len = sizeof (buffer);

	  if (len > count)
	    len = count;
	  if (read (fdorig, buffer, len) != len)
	    {
	      error (0, errno, "%s: couldn't read file", filename);
	      goto failure;
	    }
	  if (read (fd, buffer2, len) != len)
	    {
	      error (0, errno, "%s: couldn't read temporary file", filename);
	      goto failure;
	    }
	  if (memcmp (buffer, buffer2, len) != 0)
	    {
	      error (0, 0, "%s: prelinked file was modified", filename);
	      goto failure;
	    }
	  count -= len;
	}
    }

  if (handle_verify (fdundone, filename))
    goto failure;

  close (fd);
  close (fdorig);
  close (fdundone);
  return 0;

failure:
  if (fd != -1)
    close (fd);
  if (fdorig != -1)
    close (fdorig);
  if (fdundone != -1)
    close (fdundone);
  if (dso)
    close_dso (dso);
  if (dso2)
    close_dso (dso2);
  return EXIT_FAILURE;

not_prelinked:
  if (dso)
    close_dso (dso);
  fd = open (filename, O_RDONLY);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "Couldn't open %s", filename);
  if (handle_verify (fd, filename))
    return EXIT_FAILURE;
  close (fd);
  return 0;
}
