## Background

### LD.SO: dynamic linker/loader

ELF (Executable and Linkable Format) is a standard file format for executable files, object code, shared libraries and core dumps. Whenever you execute an ELF file, OS will need to load lib and link them to executables so that any shared functions are available. In Linux, id.so manages an executable prepackaged as part of the glibc library. Glibc is the GNU Project implementation of the C standard library.

    $readelf /usr/bin/man -p .interp

Usually, the required libraries are searched in a specific set of locations in the system, including the default /lib directory.

    $ldd /usr/bin/man
    
### Using DT_RPATH to Influence the Library Search Path

When compiling a program, you can specify additional paths where you want ld.so to look for libraries. These directories will be embedded in your program’s ELF file and parsed and used by ld.so when loading the executable. This allows you to override the default library search path and have your program search in an alternate location first.

    $ gcc -Wl, — enable-new-dtags -Wl,-rpath=/tmp -o myapp myapp.c

Whenever ld.so loads your executable, it will first check /tmp/ for libraries, then default to the regular library search path.

    Modifying glibc Behavior via GLIBC_TUNABLES

To better understand how this vulnerability works, let’s have a look at how the dynamic linker (ld.so) briefly works. Once it gets executed, it checks specific environment variables called GLIBC_TUNABLES. It is kind of a configuration file. Those features, aka Tunables, allow developers to dynamically alter the runtime library behavior.

    GLIBC_TUNABLES="malloc.check=1:malloc.tcache_max=128

The environment variable GLIBC_TUNABLES sets the maximum size chunk that may be stored in a tcache (in bytes).

## Analysis

The __tunables_init function takes one argument, envp, which is a pointer to an array of strings representing the environment variables. While loop iterates through the environment variables. Calls get_next_env, which retrieves the next environment variable and updates the pointers envp, envname, len, and envval. Then it checks if a tunable name is “GLBIC TUNABLE” and if so, it will duplicate via strdup. If the duplication was successful, parse_tunables is called to parse the value part (envval) of this environment variable. And finally, update it to the new envp.

This code scans through the environment variables to find one named “GLIBC_TUNABLES”. When it finds this variable, it creates a duplicate of it, parses its value, and updates the environment variable list to use this new duplicated version. This is done to potentially modify the behavior of GLIBC based on tunable parameters defined in “GLIBC_TUNABLES”

void
__tunables_init (char **envp)
{
   char *envname = NULL;
   char *envval = NULL;
   size_t len = 0;
   char **prev_envp = envp;

   while ((envp = get_next_env (envp, &envname, &len, &envval, &prev_envp)) != NULL)
{
 if (tunable_is_name ("GLIBC_TUNABLES", envname))
 {
     char *new_env = tunables_strdup (envname);
     if (new_env != NULL)
         parse_tunables (new_env + len + 1, envval);
     /* Put in the updated envval.  */
     *prev_envp = new_env;
     continue;
 }
}

Inside parse_tunables(), the code examines the copied GLIBC_TUNABLES to break it down into individual name-value pairs. It does this by searching for equal signs (=) and colons (:) in the copied data.

Here’s where it gets interesting. The code is careful about security. It removes “dangerous tunables”, specifically those marked as SXID_ERASE. Those security-related tunables instruct GLIBC to modify security attributes or permissions from a process. These attributes could include changing elevated privileges, typically associated with set-user-ID (SUID) or set-group-ID (SGID) programs.

The vulnerability occurs when GLIBC_TUNABLES contains unexpected input, like tunable1=tunable2=AAA. In this case, instead of gracefully handling it, the code copies the entire input as if it were a valid setting. This issue occurs when the tunables are of type SXID_IGNORE, which should not be removed. During the first iteration of the loop, the entire tunable1=tunable2=AAA is copied to tunestr, filling it up. Later, at lines 247–248, the code fails to increment the pointer (p) because no colon (‘:’) was found. As a result, p still points to the value of tunable1, i.e., tunable2=AAA. During the second iteration of the loop, tunable2=AAA is incorrectly appended to tunestr, causing a buffer overflow because tunestr is already full.

static void
parse_tunables (char *tunestr, char *valstring)
{
...
  char *p = tunestr;
  size_t off = 0;

  while (true)
    {
      char *name = p;
      size_t len = 0;

      /* First, find where the name ends.  */
      while (p[len] != '=' && p[len] != ':' && p[len] != '\0')
        len++;

      /* If we reach the end of the string before getting a valid name-value
         pair, bail out.  */
      if (p[len] == '\0')
        {
          if (__libc_enable_secure)
            tunestr[off] = '\0';
          return;
        }

      /* We did not find a valid name-value pair before encountering the
         colon.  */
      if (p[len]== ':')
        {
          p += len + 1;
          continue;
        }

      p += len + 1;

      /* Take the value from the valstring since we need to NULL terminate it.  */
      char *value = &valstring[p - tunestr];
      len = 0;

      while (p[len] != ':' && p[len] != '\0')
        len++;

      /* Add the tunable if it exists.  */
      for (size_t i = 0; i < sizeof (tunable_list) / sizeof (tunable_t); i++)
        {
          tunable_t *cur = &tunable_list[i];

          if (tunable_is_name (cur->name, name))
            {
              if (__libc_enable_secure)
                {
                  if (cur->security_level != TUNABLE_SECLEVEL_SXID_ERASE)
                    {
                      if (off > 0)
                        tunestr[off++] = ':';

                      const char *n = cur->name;

                      while (*n != '\0')
                        tunestr[off++] = *n++;

                      tunestr[off++] = '=';

                      for (size_t j = 0; j < len; j++)
                        tunestr[off++] = value[j];
                    }

                  if (cur->security_level != TUNABLE_SECLEVEL_NONE)
                    break;
                }

              value[len] = '\0';
              tunable_initialize (cur, value);
              break;
            }
        }

      if (p[len] != '\0')
        p += len + 1;
    }

In order to prevent this code from buffer overflow. Replace potentially unsafe functions like strcpy, strcat, or sprintf with their safer counterparts like strncpy, strncat, or snprintf, which allow specifying the buffer size to prevent overflows.

In your specific case, you can replace

    while (*n != '\0') tunestr[off++] = *n++;

with something safer:

    while (*n != '\0' && off < BUFFER_SIZE - 1) tunestr[off++] = *n++;

BUFFER_SIZE should be defined as the maximum size of tunestr.
