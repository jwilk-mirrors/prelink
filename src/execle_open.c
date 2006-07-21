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
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t pid;

int
execve_close (FILE *f)
{
  pid_t p;
  int status;

  if (f != NULL)
    fclose (f);
  while ((p = waitpid (pid, &status, 0)) == -1 && errno == EINTR);
  if (p == -1 || ! WIFEXITED (status))
    return -1;
  return WEXITSTATUS (status);
}

FILE *
execve_open (const char *path, char *const argv[], char *const envp[])
{
  int p[2];
  FILE *f;

  if (pipe (p) < 0)
    {
      error (0, errno, "Could not run %s", path);
      return NULL;
    }

  switch (vfork ())
    {
    case -1:
      error (0, errno, "Could not run %s", path);
      return NULL;
    case 0:
      close (p[0]);
      if (p[1] != 1)
	{
	  dup2 (p[1], 1);
	  close (p[1]);
	}
      dup2 (1, 2);
      execve (path, argv, envp);
      _exit (127);
    }

  close (p[1]);

  f = fdopen (p[0], "r");
  if (f == NULL)
    {
      close (p[0]);
      execve_close (NULL);
    }

  return f;
}
