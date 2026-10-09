#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include <stdarg.h>
#include <assert.h>

static void fatal (const char *format, ...) ATTRIBUTE_NORETURN;
static void
fatal (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  exit (2);
}

#if defined (__linux__) && defined (PYRO_PORTABLE_SNAPSHOTS)
#include <sys/mman.h>
/* Exercise the non-Linux adapter without allowing a Linux-only dependency. */
#pragma GCC poison memfd_create
#endif

#include "snapshot-provider.h"

static void
put_file (const char *name, const char *bytes)
{
  int fd = open (name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  assert (fd >= 0);
  assert (write (fd, bytes, strlen (bytes)) == (ssize_t) strlen (bytes));
  assert (close (fd) == 0);
}

static void
assert_readonly_snapshot (int fd)
{
  struct stat st;
  assert (fstat (fd, &st) == 0 && S_ISREG (st.st_mode) && st.st_nlink == 0);
  assert ((fcntl (fd, F_GETFL) & O_ACCMODE) == O_RDONLY);
  assert ((fcntl (fd, F_GETFD) & FD_CLOEXEC) != 0);
  assert (write (fd, "changed", 7) < 0 && errno == EBADF);
  assert (pwrite (fd, "changed", 7, 0) < 0 && errno == EBADF);
  assert (ftruncate (fd, 0) < 0);
#if defined (__linux__) && !defined (PYRO_PORTABLE_SNAPSHOTS)
  assert ((fcntl (fd, F_GET_SEALS) & F_SEAL_WRITE) != 0);
#endif
}

int
main (int argc, char **argv)
{
  const char *selected = "0123456789ABCDEFGHIJKLMNOP";
  char fd_text[32], first[8], second[8];
  char *canon, *again;
  int fd, one, two, error;
  struct stat st;
  FILE *stream;
  bfd *object;
  assert (argc == 3);
  assert (bfd_init () == BFD_INIT_MAGIC);
  put_file (argv[1], selected);
  canon = realpath (argv[1], NULL);
  assert (canon);
  fd = open (argv[1], O_RDONLY | O_CLOEXEC);
  assert (fd >= 0);
  snprintf (fd_text, sizeof fd_text, "%d", fd);
  assert (setenv ("PYRO_PRIMARY_FD", fd_text, 1) == 0);
  assert (setenv ("PYRO_PRIMARY_NAME", argv[1], 1) == 0);
  assert (setenv ("PYRO_PRIMARY_CANONICAL", canon, 1) == 0);
  snapshot_provider_init (argv[1]);
  put_file (argv[1], "replacement-is-not-the-selected-bytes");

  one = bfd_input_open (argv[1], O_RDONLY);
  two = bfd_input_open (argv[1], O_RDONLY);
  assert (one >= 0 && two >= 0);
  assert_readonly_snapshot (one);
  assert_readonly_snapshot (two);
  assert (read (one, first, 8) == 8);
  assert (read (two, second, 8) == 8);
  assert (memcmp (first, selected, 8) == 0 && memcmp (first, second, 8) == 0);
  close (one);
  close (two);
  puts ("PASS independent-open-descriptions-and-unlinked-readonly-bytes");

  object = bfd_openr (argv[1], NULL);
  assert (object && strcmp (bfd_get_filename (object), argv[1]) == 0);
  assert (bfd_stat (object, &st) == 0 && st.st_size == (off_t) strlen (selected));
  assert (bfd_read (first, 8, object) == 8 && memcmp (first, selected, 8) == 0);
  assert (bfd_cache_close_all ());
  assert (bfd_read (second, 8, object) == 8 && memcmp (second, selected + 8, 8) == 0);
  assert (bfd_close (object));
  puts ("PASS bfd-cache-close-reopen-offset-metadata-and-logical-filename");

  fd = open (argv[1], O_RDONLY | O_CLOEXEC);
  assert (fd >= 0);
  object = bfd_fdopenr (argv[1], NULL, fd);
  assert (object && bfd_read (first, 8, object) == 8);
  assert (memcmp (first, selected, 8) == 0);
  assert (bfd_close (object));
  puts ("PASS fdopen-cannot-bypass-selected-primary");

  stream = fopen (argv[1], "rb");
  assert (stream && !bfd_openstreamr (argv[1], NULL, stream));
  assert (fgetc (stream) == 'r');
  fclose (stream);
  assert (!bfd_openw (argv[1], NULL));
  stream = fopen (argv[1], "rb");
  assert (stream && fgetc (stream) == 'r');
  fclose (stream);
  puts ("PASS streams-and-writes-fail-closed-without-unlink");

  again = bfd_input_canonical_name (argv[1]);
  assert (again && strcmp (again, canon) == 0);
  free (again);
  free (canon);
  unlink (argv[2]);
  assert (mkfifo (argv[2], 0600) == 0);
  assert (bfd_input_open (argv[2], O_RDONLY) < 0);
  error = errno;
  assert (unlink (argv[2]) == 0);
  put_file (argv[2], "new-valid-file");
  assert (bfd_input_open (argv[2], O_RDONLY) < 0 && errno == error);
  puts ("PASS fifo-rejection-and-cached-failure-no-live-retry");

  {
    char *alias = concat (argv[1], ".alias", NULL);
    unlink (alias);
    assert (symlink (argv[1], alias) == 0);
    one = bfd_input_open (alias, O_RDONLY);
    assert (one >= 0 && read (one, first, 8) == 8);
    assert (memcmp (first, selected, 8) == 0);
    close (one);
    assert (unlink (alias) == 0 && symlink (argv[2], alias) == 0);
    one = bfd_input_open (alias, O_RDONLY);
    assert (one >= 0 && read (one, second, 8) == 8);
    assert (memcmp (first, second, 8) == 0);
    close (one);
    again = bfd_input_canonical_name (alias);
    canon = realpath (argv[1], NULL);
    assert (canon && strcmp (again, canon) == 0);
    free (canon);
    free (again);
    unlink (alias);
    free (alias);
    puts ("PASS canonical-alias-deduplication-and-symlink-retarget-stability");
  }

  {
    char *auxiliary = concat (argv[2], ".captured", NULL);
    put_file (auxiliary, selected);
    fd = open (auxiliary, O_RDONLY | O_CLOEXEC);
    assert (fd >= 0 && lseek (fd, 8, SEEK_SET) == 8);
    one = snapshot_copy (fd);
    assert (one >= 0 && lseek (fd, 0, SEEK_CUR) == 8);
    assert (pread (one, first, 8, 0) == 8 && memcmp (first, selected, 8) == 0);
    close (one);
    close (fd);
    one = bfd_input_open (auxiliary, O_RDONLY);
    assert (one >= 0);
    assert_readonly_snapshot (one);
    put_file (auxiliary, "in-place-replacement");
    two = bfd_input_open (auxiliary, O_RDONLY);
    assert (two >= 0);
    assert_readonly_snapshot (two);
    assert (read (one, first, 8) == 8 && memcmp (first, selected, 8) == 0);
    assert (read (two, second, 8) == 8 && memcmp (first, second, 8) == 0);
    close (one);
    close (two);
    assert (unlink (auxiliary) == 0);
    one = bfd_input_open (auxiliary, O_RDONLY);
    assert (one >= 0 && read (one, first, 8) == 8);
    assert (memcmp (first, selected, 8) == 0);
    close (one);
    free (auxiliary);
    puts ("PASS auxiliary-snapshot-survives-rewrite-and-unlink");
  }
#if !defined (__linux__) || defined (PYRO_PORTABLE_SNAPSHOTS)
  {
    const char *temporary_root = getenv ("TMPDIR");
    char *saved = temporary_root ? xstrdup (temporary_root) : NULL;
    fd = open (argv[1], O_RDONLY | O_CLOEXEC);
    assert (fd >= 0);
    assert (setenv ("TMPDIR", argv[1], 1) == 0);
    assert (snapshot_copy (fd) < 0 && errno == ENOTDIR);
    if (saved)
      {
        assert (setenv ("TMPDIR", saved, 1) == 0);
        free (saved);
      }
    else
      assert (unsetenv ("TMPDIR") == 0);
    one = snapshot_copy (fd);
    assert (one >= 0);
    assert_readonly_snapshot (one);
    close (one);
    close (fd);
    puts ("PASS failed-portable-storage-does-not-fall-back-to-linux-or-live-input");
  }
#endif
  return 0;
}
