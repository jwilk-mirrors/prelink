/* Copyright (C) 2002, 2005 Red Hat, Inc.
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
#include <alloca.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "prelinktab.h"

static int
undo_one (void **p, void *info)
{
  struct prelink_entry *ent = * (struct prelink_entry **) p;
  DSO *dso;
  struct stat64 st;
  struct prelink_link *hardlink;
  char *move = NULL;
  size_t movelen = 0;

  if (ent->done != 2)
    return 1;

  if (ent->type != ET_DYN
      && (ent->type != ET_EXEC || libs_only))
    return 1;

  dso = open_dso (ent->canon_filename);
  if (dso == NULL)
    goto error_out;

  if (fstat64 (dso->fd, &st) < 0)
    {
      error (0, errno, "%s changed during prelinking", ent->filename);
      goto error_out;
    }

  if (st.st_dev != ent->dev || st.st_ino != ent->ino)
    {
      error (0, 0, "%s changed during prelinking", ent->filename);
      goto error_out;
    }

  if (verbose)
    {
      if (dry_run)
	printf ("Would undo %s\n", ent->canon_filename);
      else
	printf ("Undoing %s\n", ent->canon_filename);
    }

  if (prelink_undo (dso))
    goto error_out;

  if (dry_run)
    close_dso (dso);
  else
    {
      if (update_dso (dso, NULL))
	{
	  dso = NULL;
	  goto error_out;
	}
    }

  dso = NULL;

  /* Redo hardlinks.  */
  for (hardlink = ent->hardlink; hardlink; hardlink = hardlink->next)
    {
      size_t len;

      if (lstat64 (hardlink->canon_filename, &st) < 0)
	{
	  error (0, 0, "Could not stat %s (former hardlink to %s)",
		 hardlink->canon_filename, ent->canon_filename);
	  continue;
	}

      if (st.st_dev != ent->dev || st.st_ino != ent->ino)
	{
	  error (0, 0, "%s is no longer hardlink to %s",
		 hardlink->canon_filename, ent->canon_filename);
	  continue;
	}

      if (verbose)
	{
	  if (dry_run)
	    printf ("Would link %s to %s\n", hardlink->canon_filename,
		    ent->canon_filename);
	  else
	    printf ("Linking %s to %s\n", hardlink->canon_filename,
		    ent->canon_filename);
	}

      len = strlen (hardlink->canon_filename);
      if (len + sizeof (".#prelink#") > movelen)
	{
	  movelen = len + sizeof (".#prelink#");
	  move = realloc (move, movelen);
	  if (move == NULL)
	    {
	      error (0, ENOMEM, "Could not hardlink %s to %s",
		     hardlink->canon_filename, ent->canon_filename);
	      movelen = 0;
	      continue;
	    }
	}

      memcpy (mempcpy (move, hardlink->canon_filename, len), ".#prelink#",
	      sizeof (".#prelink#"));
      if (rename (hardlink->canon_filename, move) < 0)
	{
	  error (0, errno, "Could not hardlink %s to %s",
		 hardlink->canon_filename, ent->canon_filename);
	  continue;
	}

      if (link (ent->canon_filename, hardlink->canon_filename) < 0)
	{
	  error (0, errno, "Could not hardlink %s to %s",
		 hardlink->canon_filename, ent->canon_filename);

	  if (rename (move, hardlink->canon_filename) < 0)
	    {
	      error (0, errno, "Could not rename %s back to %s",
		     move, hardlink->canon_filename);
	    }
	  continue;
	}

      if (unlink (move) < 0)
	{
	  error (0, errno, "Could not unlink %s", move);
	  continue;
	}
    }
  free (move);
  return 1;

error_out:
  if (dso)
    close_dso (dso);
  (*(int *)info)++;
  return 1;
}

int
undo_all (void)
{
  int failures = 0;
  htab_traverse (prelink_filename_htab, undo_one, &failures);
  return failures != 0;
}
