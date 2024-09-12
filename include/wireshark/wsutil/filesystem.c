/* filesystem.c
 * Filesystem utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "filesystem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <shlobj.h>
#include <wsutil/unicode-utils.h>
#else /* _WIN32 */
#ifdef ENABLE_APPLICATION_BUNDLE
#include <mach-o/dyld.h>
#endif
#ifdef __linux__
#include <sys/utsname.h>
#endif
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#ifdef HAVE_DLGET
#include <dlfcn.h>
#endif
#include <pwd.h>
#endif /* _WIN32 */

#include <wsutil/report_message.h>
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include <wsutil/utf8_entities.h>

#include <wiretap/wtap.h>   /* for WTAP_ERR_SHORT_WRITE */

#include "path_config.h"

#define PROFILES_DIR    "profiles"
#define PLUGINS_DIR_NAME    "plugins"
#define EXTCAP_DIR_NAME     "extcap"
#define PROFILES_INFO_NAME  "profile_files.txt"

#define _S G_DIR_SEPARATOR_S

/*
 * Application configuration namespace. Used to construct configuration
 * paths and environment variables.
 * XXX We might want to use the term "application flavor" instead, with
 * "packet" and "log" flavors.
 */
enum configuration_namespace_e {
    CONFIGURATION_NAMESPACE_UNINITIALIZED,
    CONFIGURATION_NAMESPACE_WIRESHARK,
    CONFIGURATION_NAMESPACE_LOGRAY
};
enum configuration_namespace_e configuration_namespace = CONFIGURATION_NAMESPACE_UNINITIALIZED;

#define CONFIGURATION_NAMESPACE_PROPER (configuration_namespace == CONFIGURATION_NAMESPACE_WIRESHARK ? "Wireshark" : "Logray")
#define CONFIGURATION_NAMESPACE_LOWER (configuration_namespace == CONFIGURATION_NAMESPACE_WIRESHARK ? "wireshark" : "logray")
#define CONFIGURATION_ENVIRONMENT_VARIABLE(suffix) (configuration_namespace == CONFIGURATION_NAMESPACE_WIRESHARK ? "WIRESHARK_" suffix : "LOGRAY_" suffix)

char *persconffile_dir;
char *datafile_dir;
char *persdatafile_dir;
char *persconfprofile;
char *doc_dir;
char *current_working_dir;

/* Directory from which the executable came. */
static char *progfile_dir;
static char *install_prefix;

static bool do_store_persconffiles;
static GHashTable *profile_files;

/*
 * Given a pathname, return a pointer to the last pathname separator
 * character in the pathname, or NULL if the pathname contains no
 * separators.
 */
char *
find_last_pathname_separator(const char *path)
{
    char *separator;

#ifdef _WIN32
    char c;

    /*
     * We have to scan for '\' or '/'.
     * Get to the end of the string.
     */
    separator = strchr(path, '\0');     /* points to ending '\0' */
    while (separator > path) {
        c = *--separator;
        if (c == '\\' || c == '/')
            return separator;   /* found it */
    }

    /*
     * OK, we didn't find any, so no directories - but there might
     * be a drive letter....
     */
    return strchr(path, ':');
#else
    separator = strrchr(path, '/');
    return separator;
#endif
}

/*
 * Given a pathname, return the last component.
 */
const char *
get_basename(const char *path)
{
    const char *filename;

    ws_assert(path != NULL);
    filename = find_last_pathname_separator(path);
    if (filename == NULL) {
        /*
         * There're no directories, drive letters, etc. in the
         * name; the pathname *is* the file name.
         */
        filename = path;
    } else {
        /*
         * Skip past the pathname or drive letter separator.
         */
        filename++;
    }
    return filename;
}

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
char *
get_dirname(char *path)
{
    char *separator;

    ws_assert(path != NULL);
    separator = find_last_pathname_separator(path);
    if (separator == NULL) {
        /*
         * There're no directories, drive letters, etc. in the
         * name; there is no directory path to return.
         */
        return NULL;
    }

    /*
     * Get rid of the last pathname separator and the final file
     * name following it.
     */
    *separator = '\0';

    /*
     * "path" now contains the pathname of the directory containing
     * the file/directory to which it referred.
     */
    return path;
}

/*
 * Given a pathname, return:
 *
 *  the errno, if an attempt to "stat()" the file fails;
 *
 *  EISDIR, if the attempt succeeded and the file turned out
 *  to be a directory;
 *
 *  0, if the attempt succeeded and the file turned out not
 *  to be a directory.
 */

int
test_for_directory(const char *path)
{
    ws_statb64 statb;

    if (ws_stat64(path, &statb) < 0)
        return errno;

    if (S_ISDIR(statb.st_mode))
        return EISDIR;
    else
        return 0;
}

int
test_for_fifo(const char *path)
{
    ws_statb64 statb;

    if (ws_stat64(path, &statb) < 0)
        return errno;

    if (S_ISFIFO(statb.st_mode))
        return ESPIPE;
    else
        return 0;
}

bool
test_for_regular_file(const char *path)
{
    ws_statb64 statb;

    if (!path) {
        return false;
    }

    if (ws_stat64(path, &statb) != 0)
        return false;

    return S_ISREG(statb.st_mode);
}

#ifdef ENABLE_APPLICATION_BUNDLE
/*
 * Directory of the application bundle in which we're contained,
 * if we're contained in an application bundle.  Otherwise, NULL.
 *
 * Note: Table 2-5 "Subdirectories of the Contents directory" of
 *
 *    https://developer.apple.com/library/mac/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html#//apple_ref/doc/uid/10000123i-CH101-SW1
 *
 * says that the "Frameworks" directory
 *
 *    Contains any private shared libraries and frameworks used by the
 *    executable.  The frameworks in this directory are revision-locked
 *    to the application and cannot be superseded by any other, even
 *    newer, versions that may be available to the operating system.  In
 *    other words, the frameworks included in this directory take precedence
 *    over any other similarly named frameworks found in other parts of
 *    the operating system.  For information on how to add private
 *    frameworks to your application bundle, see Framework Programming Guide.
 *
 * so if we were to ship with any frameworks (e.g. Qt) we should
 * perhaps put them in a Frameworks directory rather than under
 * Resources.
 *
 * It also says that the "PlugIns" directory
 *
 *    Contains loadable bundles that extend the basic features of your
 *    application. You use this directory to include code modules that
 *    must be loaded into your applicationbs process space in order to
 *    be used. You would not use this directory to store standalone
 *    executables.
 *
 * Our plugins are just raw .so/.dylib files; I don't know whether by
 * "bundles" they mean application bundles (i.e., directory hierarchies)
 * or just "bundles" in the Mach-O sense (which are an image type that
 * can be loaded with dlopen() but not linked as libraries; our plugins
 * are, I think, built as dylibs and can be loaded either way).
 *
 * And it says that the "SharedSupport" directory
 *
 *    Contains additional non-critical resources that do not impact the
 *    ability of the application to run. You might use this directory to
 *    include things like document templates, clip art, and tutorials
 *    that your application expects to be present but that do not affect
 *    the ability of your application to run.
 *
 * I don't think I'd put the files that currently go under Resources/share
 * into that category; they're not, for example, sample Lua scripts that
 * don't actually get run by Wireshark, they're configuration/data files
 * for Wireshark whose absence might not prevent Wireshark from running
 * but that would affect how it behaves when run.
 */
static char *appbundle_dir;
#endif

/*
 * true if we're running from the build directory and we aren't running
 * with special privileges.
 */
static bool running_in_build_directory_flag;

/*
 * Set our configuration namespace. This will be used for top-level
 * configuration directory names and environment variable prefixes.
 */
static void
set_configuration_namespace(const char *namespace_name)
{

    if (configuration_namespace != CONFIGURATION_NAMESPACE_UNINITIALIZED) {
        return;
    }

    if (!namespace_name || g_ascii_strcasecmp(namespace_name, "wireshark") == 0)
    {
        configuration_namespace = CONFIGURATION_NAMESPACE_WIRESHARK;
    }
    else if (g_ascii_strcasecmp(namespace_name, "logray") == 0)
    {
        configuration_namespace = CONFIGURATION_NAMESPACE_LOGRAY;
    }
    else
    {
        ws_error("Unknown configuration namespace %s", namespace_name);
    }

    ws_debug("Using configuration namespace %s.", CONFIGURATION_NAMESPACE_PROPER);
}

const char *
get_configuration_namespace(void)
{
    return CONFIGURATION_NAMESPACE_PROPER;
}

bool is_packet_configuration_namespace(void)
{
    return configuration_namespace != CONFIGURATION_NAMESPACE_LOGRAY;
}

#ifndef _WIN32
/*
 * Get the pathname of the executable using various platform-
 * dependent mechanisms for various UN*Xes.
 *
 * These calls all should return something independent of the argv[0]
 * passed to the program, so it shouldn't be fooled by an argv[0]
 * that doesn't match the executable path.
 *
 * We don't use dladdr() because:
 *
 *   not all UN*Xes necessarily have dladdr();
 *
 *   those that do have it don't necessarily have dladdr(main)
 *   return information about the executable image;
 *
 *   those that do have a dladdr() where dladdr(main) returns
 *   information about the executable image don't necessarily
 *   have a mechanism by which the executable image can get
 *   its own path from the kernel (either by a call or by it
 *   being handed to it along with argv[] and the environment),
 *   so they just fall back on getting it from argv[0], which we
 *   already have code to do;
 *
 *   those that do have such a mechanism don't necessarily use
 *   it in dladdr(), and, instead, just fall back on getting it
 *   from argv[0];
 *
 * so the only places where it's worth bothering to use dladdr()
 * are platforms where dladdr(main) return information about the
 * executable image by getting it from the kernel rather than
 * by looking at argv[0], and where we can't get at that information
 * ourselves, and we haven't seen any indication that there are any
 * such platforms.
 *
 * In particular, some dynamic linkers supply a dladdr() such that
 * dladdr(main) just returns something derived from argv[0], so
 * just using dladdr(main) is the wrong thing to do if there's
 * another mechanism that can get you a more reliable version of
 * the executable path.
 *
 * So, on platforms where we know of a mechanism to get that path
 * (where getting that path doesn't involve argv[0], which is not
 * guaranteed to reflect the path to the binary), this routine
 * attempsts to use that platform's mechanism.  On other platforms,
 * it just returns NULL.
 *
 * This is not guaranteed to return an absolute path; if it doesn't,
 * our caller must prepend the current directory if it's a path.
 *
 * This is not guaranteed to return the "real path"; it might return
 * something with symbolic links in the path.  Our caller must
 * use realpath() if they want the real thing, but that's also true of
 * something obtained by looking at argv[0].
 */
#define xx_free free  /* hack so checkAPIs doesn't complain */
static const char *
get_current_executable_path(void)
{
#if defined(ENABLE_APPLICATION_BUNDLE)
    static char *executable_path;
    uint32_t path_buf_size;

    if (executable_path) {
        return executable_path;
    }

    path_buf_size = PATH_MAX;
    executable_path = (char *)g_malloc(path_buf_size);
    if (_NSGetExecutablePath(executable_path, &path_buf_size) == -1) {
        executable_path = (char *)g_realloc(executable_path, path_buf_size);
        if (_NSGetExecutablePath(executable_path, &path_buf_size) == -1)
            return NULL;
    }
    /*
     * Resolve our path so that it's possible to symlink the executables
     * in our application bundle.
     */
    char *rp_execpath = realpath(executable_path, NULL);
    if (rp_execpath) {
        g_free(executable_path);
        executable_path = g_strdup(rp_execpath);
        xx_free(rp_execpath);
    }
    return executable_path;
#elif defined(__linux__)
    /*
     * In older versions of GNU libc's dynamic linker, as used on Linux,
     * dladdr(main) supplies a path based on argv[0], so we use
     * /proc/self/exe instead; there are Linux distributions with
     * kernels that support /proc/self/exe and those older versions
     * of the dynamic linker, and this will get a better answer on
     * those versions.
     *
     * It only works on Linux 2.2 or later, so we just give up on
     * earlier versions.
     *
     * XXX - are there OS versions that support "exe" but not "self"?
     */
    struct utsname name;
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if (uname(&name) == -1)
        return NULL;
    if (strncmp(name.release, "1.", 2) == 0)
        return NULL; /* Linux 1.x */
    if (strcmp(name.release, "2.0") == 0 ||
        strncmp(name.release, "2.0.", 4) == 0 ||
        strcmp(name.release, "2.1") == 0 ||
        strncmp(name.release, "2.1.", 4) == 0)
        return NULL; /* Linux 2.0.x or 2.1.x */
    if ((r = readlink("/proc/self/exe", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(__FreeBSD__) && defined(KERN_PROC_PATHNAME)
    /*
     * In older versions of FreeBSD's dynamic linker, dladdr(main)
     * supplies a path based on argv[0], so we use the KERN_PROC_PATHNAME
     * sysctl instead; there are, I think, versions of FreeBSD
     * that support the sysctl that have and those older versions
     * of the dynamic linker, and this will get a better answer on
     * those versions.
     */
    int mib[4];
    char *executable_path;
    size_t path_buf_size;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = -1;
    path_buf_size = PATH_MAX;
    executable_path = (char *)g_malloc(path_buf_size);
    if (sysctl(mib, 4, executable_path, &path_buf_size, NULL, 0) == -1) {
        if (errno != ENOMEM)
            return NULL;
        executable_path = (char *)g_realloc(executable_path, path_buf_size);
        if (sysctl(mib, 4, executable_path, &path_buf_size, NULL, 0) == -1)
            return NULL;
    }
    return executable_path;
#elif defined(__NetBSD__)
    /*
     * In all versions of NetBSD's dynamic linker as of 2013-08-12,
     * dladdr(main) supplies a path based on argv[0], so we use
     * /proc/curproc/exe instead.
     *
     * XXX - are there OS versions that support "exe" but not "curproc"
     * or "self"?  Are there any that support "self" but not "curproc"?
     */
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if ((r = readlink("/proc/curproc/exe", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(__DragonFly__)
    /*
     * In older versions of DragonFly BSD's dynamic linker, dladdr(main)
     * supplies a path based on argv[0], so we use /proc/curproc/file
     * instead; it appears to be supported by all versions of DragonFly
     * BSD.
     */
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if ((r = readlink("/proc/curproc/file", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(HAVE_GETEXECNAME)
    /*
     * Solaris, with getexecname().
     * It appears that getexecname() dates back to at least Solaris 8,
     * but /proc/{pid}/path is first documented in the Solaris 10 documentation,
     * so we use getexecname() if available, rather than /proc/self/path/a.out
     * (which isn't documented, but appears to be a symlink to the
     * executable image file).
     */
    return getexecname();
#elif defined(HAVE_DLGET)
    /*
     * HP-UX 11, with dlget(); use dlget() and dlgetname().
     * See
     *
     *  https://web.archive.org/web/20081025174755/http://h21007.www2.hp.com/portal/site/dspp/menuitem.863c3e4cbcdc3f3515b49c108973a801?ciid=88086d6e1de021106d6e1de02110275d6e10RCRD#two
     */
    struct load_module_desc desc;

    if (dlget(-2, &desc, sizeof(desc)) != NULL)
        return dlgetname(&desc, sizeof(desc), NULL, NULL, NULL);
    else
        return NULL;
#else
    /* Fill in your favorite UN*X's code here, if there is something */
    return NULL;
#endif
}
#endif /* _WIN32 */

static void trim_progfile_dir(void)
{
#ifdef _WIN32
    char *namespace_last_dir = find_last_pathname_separator(progfile_dir);
    if (namespace_last_dir && strncmp(namespace_last_dir + 1, CONFIGURATION_NAMESPACE_LOWER, sizeof(CONFIGURATION_NAMESPACE_LOWER)) == 0) {
        *namespace_last_dir = '\0';
    }
#endif

    char *progfile_last_dir = find_last_pathname_separator(progfile_dir);

    if (! (progfile_last_dir && strncmp(progfile_last_dir + 1, "extcap", sizeof("extcap")) == 0)) {
        return;
    }

    *progfile_last_dir = '\0';
    char *extcap_progfile_dir = progfile_dir;
    progfile_dir = g_strdup(extcap_progfile_dir);
    g_free(extcap_progfile_dir);
}

#if !defined(_WIN32) || defined(HAVE_MSYSTEM)
static char *
trim_last_dir_from_path(const char *_path)
{
    char *path = ws_strdup(_path);
    char *last_dir = find_last_pathname_separator(path);
    if (last_dir) {
        *last_dir = '\0';
    }
    return path;
}
#endif

/*
 * Construct the path name of a non-extcap Wireshark executable file,
 * given the program name.  The executable name doesn't include ".exe";
 * append it on Windows, so that callers don't have to worry about that.
 *
 * This presumes that all non-extcap executables are in the same directory.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
char *
get_executable_path(const char *program_name)
{
    /*
     * Fail if we don't know what directory contains the executables.
     */
    if (progfile_dir == NULL)
        return NULL;

#ifdef _WIN32
    return ws_strdup_printf("%s\\%s.exe", progfile_dir, program_name);
#else
    return ws_strdup_printf("%s/%s", progfile_dir, program_name);
#endif
}

/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.  Returns NULL on success, and a
 * g_mallocated string containing an error on failure.
 */
#ifdef _WIN32
static char *
configuration_init_w32(const char* arg0 _U_)
{
    TCHAR prog_pathname_w[_MAX_PATH+2];
    char *prog_pathname;
    DWORD error;
    TCHAR *msg_w;
    unsigned char *msg;
    size_t msglen;

    /*
     * Attempt to get the full pathname of the currently running
     * program.
     */
    if (GetModuleFileName(NULL, prog_pathname_w, G_N_ELEMENTS(prog_pathname_w)) != 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        /*
         * XXX - Should we use g_utf16_to_utf8()?
         */
        prog_pathname = utf_16to8(prog_pathname_w);
        /*
         * We got it; strip off the last component, which would be
         * the file name of the executable, giving us the pathname
         * of the directory where the executable resides.
         */
        progfile_dir = g_path_get_dirname(prog_pathname);
        if (progfile_dir != NULL) {
            trim_progfile_dir();
            /* we succeeded */
        } else {
            /*
             * OK, no. What do we do now?
             */
            return ws_strdup_printf("No \\ in executable pathname \"%s\"",
                prog_pathname);
        }
    } else {
        /*
         * Oh, well.  Return an indication of the error.
         */
        error = GetLastError();
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, 0, (LPTSTR) &msg_w, 0, NULL) == 0) {
            /*
             * Gak.  We can't format the message.
             */
            return ws_strdup_printf("GetModuleFileName failed: %lu (FormatMessage failed: %lu)",
                error, GetLastError());
        }
        msg = utf_16to8(msg_w);
        LocalFree(msg_w);
        /*
         * "FormatMessage()" "helpfully" sticks CR/LF at the
         * end of the message.  Get rid of it.
         */
        msglen = strlen(msg);
        if (msglen >= 2) {
            msg[msglen - 1] = '\0';
            msg[msglen - 2] = '\0';
        }
        return ws_strdup_printf("GetModuleFileName failed: %s (%lu)",
            msg, error);
    }

#ifdef HAVE_MSYSTEM
    /*
     * We already have the program_dir. Find the installation prefix.
     * This is one level up from the bin_dir. If the program_dir does
     * not end with "bin" then assume we are running in the build directory
     * and the "installation prefix" (staging directory) is the same as
     * the program_dir.
     */
    if (g_str_has_suffix(progfile_dir, _S"bin")) {
        install_prefix = trim_last_dir_from_path(progfile_dir);
    }
    else {
        install_prefix = g_strdup(progfile_dir);
        running_in_build_directory_flag = true;
    }
#endif /* HAVE_MSYSTEM */

    return NULL;
}

#else /* !_WIN32 */

static char *
configuration_init_posix(const char* arg0)
{
    const char *execname;
    char *prog_pathname;
    char *curdir;
    long path_max;
    const char *pathstr;
    const char *path_start, *path_end;
    size_t path_component_len, path_len;
    char *retstr;
    char *path;
    char *dir_end;

    /* Hard-coded value used if we cannot obtain the path of the running executable. */
    install_prefix = g_strdup(INSTALL_PREFIX);

    /*
     * Check whether XXX_RUN_FROM_BUILD_DIRECTORY is set in the
     * environment; if so, set running_in_build_directory_flag if we
     * weren't started with special privileges.  (If we were started
     * with special privileges, it's not safe to allow the user to point
     * us to some other directory; running_in_build_directory_flag, when
     * set, causes us to look for plugins and the like in the build
     * directory.)
     */
    const char *run_from_envar = CONFIGURATION_ENVIRONMENT_VARIABLE("RUN_FROM_BUILD_DIRECTORY");
    if (g_getenv(run_from_envar) != NULL
        && !started_with_special_privs()) {
        running_in_build_directory_flag = true;
    }

    execname = get_current_executable_path();
    if (execname == NULL) {
        /*
         * OK, guess based on argv[0].
         */
        execname = arg0;
    }

    /*
     * Try to figure out the directory in which the currently running
     * program resides, given something purporting to be the executable
     * name (from an OS mechanism or from the argv[0] it was started with).
     * That might be the absolute path of the program, or a path relative
     * to the current directory of the process that started it, or
     * just a name for the program if it was started from the command
     * line and was searched for in $PATH.  It's not guaranteed to be
     * any of those, however, so there are no guarantees....
     */
    if (execname[0] == '/') {
        /*
         * It's an absolute path.
         */
        prog_pathname = g_strdup(execname);
    } else if (strchr(execname, '/') != NULL) {
        /*
         * It's a relative path, with a directory in it.
         * Get the current directory, and combine it
         * with that directory.
         */
        path_max = pathconf(".", _PC_PATH_MAX);
        if (path_max == -1) {
            /*
             * We have no idea how big a buffer to
             * allocate for the current directory.
             */
            return ws_strdup_printf("pathconf failed: %s\n",
                g_strerror(errno));
        }
        curdir = (char *)g_malloc(path_max);
        if (getcwd(curdir, path_max) == NULL) {
            /*
             * It failed - give up, and just stick
             * with DATA_DIR.
             */
            g_free(curdir);
            return ws_strdup_printf("getcwd failed: %s\n",
                g_strerror(errno));
        }
        path = ws_strdup_printf("%s/%s", curdir, execname);
        g_free(curdir);
        prog_pathname = path;
    } else {
        /*
         * It's just a file name.
         * Search the path for a file with that name
         * that's executable.
         */
        prog_pathname = NULL;   /* haven't found it yet */
        pathstr = g_getenv("PATH");
        path_start = pathstr;
        if (path_start != NULL) {
            while (*path_start != '\0') {
                path_end = strchr(path_start, ':');
                if (path_end == NULL)
                    path_end = path_start + strlen(path_start);
                path_component_len = path_end - path_start;
                path_len = path_component_len + 1
                    + strlen(execname) + 1;
                path = (char *)g_malloc(path_len);
                memcpy(path, path_start, path_component_len);
                path[path_component_len] = '\0';
                (void) g_strlcat(path, "/", path_len);
                (void) g_strlcat(path, execname, path_len);
                if (access(path, X_OK) == 0) {
                    /*
                     * Found it!
                     */
                    prog_pathname = path;
                    break;
                }

                /*
                 * That's not it.  If there are more
                 * path components to test, try them.
                 */
                if (*path_end == ':')
                    path_end++;
                path_start = path_end;
                g_free(path);
            }
            if (prog_pathname == NULL) {
                /*
                 * Program not found in path.
                 */
                return ws_strdup_printf("\"%s\" not found in \"%s\"",
                    execname, pathstr);
            }
        } else {
            /*
             * PATH isn't set.
             * XXX - should we pick a default?
             */
            return g_strdup("PATH isn't set");
        }
    }

    /*
     * OK, we have what we think is the pathname
     * of the program.
     *
     * First, find the last "/" in the directory,
     * as that marks the end of the directory pathname.
     */
    dir_end = strrchr(prog_pathname, '/');
    if (dir_end != NULL) {
        /*
         * Found it.  Strip off the last component,
         * as that's the path of the program.
         */
        *dir_end = '\0';

        /*
         * Is there a "/run" at the end?
         */
        dir_end = strrchr(prog_pathname, '/');
        if (dir_end != NULL) {
            if (!started_with_special_privs()) {
                /*
                 * Check for the CMake output directory. As people may name
                 * their directories "run" (really?), also check for the
                 * CMakeCache.txt file before assuming a CMake output dir.
                 */
                if (strcmp(dir_end, "/run") == 0) {
                    char *cmake_file;
                    cmake_file = ws_strdup_printf("%.*s/CMakeCache.txt",
                                                 (int)(dir_end - prog_pathname),
                                                 prog_pathname);
                    if (file_exists(cmake_file))
                        running_in_build_directory_flag = true;
                    g_free(cmake_file);
                }
#ifdef ENABLE_APPLICATION_BUNDLE
                {
                    /*
                     * Scan up the path looking for a component
                     * named "Contents".  If we find it, we assume
                     * we're in a bundle, and that the top-level
                     * directory of the bundle is the one containing
                     * "Contents".
                     *
                     * Not all executables are in the Contents/MacOS
                     * directory, so we can't just check for those
                     * in the path and strip them off.
                     *
                     * XXX - should we assume that it's either
                     * Contents/MacOS or Resources/bin?
                     */
                    char *component_end, *p;

                    component_end = strchr(prog_pathname, '\0');
                    p = component_end;
                    for (;;) {
                        while (p >= prog_pathname && *p != '/')
                            p--;
                        if (p == prog_pathname) {
                            /*
                             * We're looking at the first component of
                             * the pathname now, so we're definitely
                             * not in a bundle, even if we're in
                             * "/Contents".
                             */
                            break;
                        }
                        if (strncmp(p, "/Contents", component_end - p) == 0) {
                            /* Found it. */
                            appbundle_dir = (char *)g_malloc(p - prog_pathname + 1);
                            memcpy(appbundle_dir, prog_pathname, p - prog_pathname);
                            appbundle_dir[p - prog_pathname] = '\0';
                            break;
                        }
                        component_end = p;
                        p--;
                    }
                }
#endif
            }
        }

        /*
         * OK, we have the path we want.
         */
        progfile_dir = prog_pathname;
        trim_progfile_dir();
    } else {
        /*
         * This "shouldn't happen"; we apparently
         * have no "/" in the pathname.
         * Just free up prog_pathname.
         */
        retstr = ws_strdup_printf("No / found in \"%s\"", prog_pathname);
        g_free(prog_pathname);
        return retstr;
    }

    /*
     * We already have the program_dir. Find the installation prefix.
     * This is one level up from the bin_dir. If the program_dir does
     * not end with "bin" then assume we are running in the build directory
     * and the "installation prefix" (staging directory) is the same as
     * the program_dir.
     */
    g_free(install_prefix);
    if (g_str_has_suffix(progfile_dir, _S"bin")) {
        install_prefix = trim_last_dir_from_path(progfile_dir);
    }
    else {
        install_prefix = g_strdup(progfile_dir);
        running_in_build_directory_flag = true;
    }

    return NULL;
}
#endif /* ?_WIN32 */

char *
configuration_init(const char* arg0, const char *namespace_name)
{
    set_configuration_namespace(namespace_name);

#ifdef _WIN32
    return configuration_init_w32(arg0);
#else
    return configuration_init_posix(arg0);
#endif
}

/*
 * Get the directory in which the program resides.
 */
const char *
get_progfile_dir(void)
{
    return progfile_dir;
}

extern const char *
get_current_working_dir(void)
{
    if (current_working_dir != NULL) {
        return current_working_dir;
    }

    /*
     * It's good to cache this because on Windows Microsoft cautions
     * against using GetCurrentDirectory except early on, e.g. when
     * parsing command line options.
     */
    current_working_dir = g_get_current_dir();
    /*
     * The above always returns something, with a fallback, e.g., on macOS
     * if the program is run from Finder, of G_DIR_SEPARATOR_S.
     * On Windows when run from a shortcut / taskbar it returns whatever
     * the "run in" directory is on the shortcut, which is usually the
     * directory where the program resides, which isn't that useful.
     * Should we set it to the home directory on macOS or the
     * "My Documents" folder on Windows in those cases,
     * as we do in get_persdatafile_dir()? This isn't the default preference
     * setting so perhaps caveat emptor is ok.
     */
    return current_working_dir;
}

/*
 * Get the directory in which the global configuration and data files are
 * stored.
 *
 * On Windows, we use the directory in which the executable for this
 * process resides.
 *
 * On macOS (when executed from an app bundle), use a directory within
 * that app bundle.
 *
 * Otherwise, if the program was executed from the build directory, use the
 * directory in which the executable for this process resides. In all other
 * cases, use the DATA_DIR value that was set at compile time.
 *
 * XXX - if we ever make libwireshark a real library, used by multiple
 * applications (more than just TShark and versions of Wireshark with
 * various UIs), should the configuration files belong to the library
 * (and be shared by all those applications) or to the applications?
 *
 * If they belong to the library, that could be done on UNIX by the
 * configure script, but it's trickier on Windows, as you can't just
 * use the pathname of the executable.
 *
 * If they belong to the application, that could be done on Windows
 * by using the pathname of the executable, but we'd have to have it
 * passed in as an argument, in some call, on UNIX.
 *
 * Note that some of those configuration files might be used by code in
 * libwireshark, some of them might be used by dissectors (would they
 * belong to libwireshark, the application, or a separate library?),
 * and some of them might be used by other code (the Wireshark preferences
 * file includes resolver preferences that control the behavior of code
 * in libwireshark, dissector preferences, and UI preferences, for
 * example).
 */
const char *
get_datafile_dir(void)
{
    if (datafile_dir != NULL)
        return datafile_dir;

    const char *data_dir_envar = CONFIGURATION_ENVIRONMENT_VARIABLE("DATA_DIR");
    if (g_getenv(data_dir_envar) && !started_with_special_privs()) {
        /*
         * The user specified a different directory for data files
         * and we aren't running with special privileges.
         * Let {WIRESHARK,LOGRAY}_DATA_DIR take precedence.
         * XXX - We might be able to dispense with the priv check
         */
        datafile_dir = g_strdup(g_getenv(data_dir_envar));
        return datafile_dir;
    }

#if defined(HAVE_MSYSTEM)
    if (running_in_build_directory_flag) {
        datafile_dir = g_strdup(install_prefix);
    } else {
        datafile_dir = g_build_filename(install_prefix, DATA_DIR, CONFIGURATION_NAMESPACE_LOWER, (char *)NULL);
    }
#elif defined(_WIN32)
    /*
     * Do we have the pathname of the program?  If so, assume we're
     * running an installed version of the program.  If we fail,
     * we don't change "datafile_dir", and thus end up using the
     * default.
     *
     * XXX - does NSIS put the installation directory into
     * "\HKEY_LOCAL_MACHINE\SOFTWARE\Wireshark\InstallDir"?
     * If so, perhaps we should read that from the registry,
     * instead.
     */
    if (progfile_dir != NULL) {
        /*
         * Yes, we do; use that.
         */
        datafile_dir = g_strdup(progfile_dir);
    } else {
        /*
         * No, we don't.
         * Fall back on the default installation directory.
         */
        datafile_dir = g_strdup("C:\\Program Files\\Wireshark\\");
    }
#else
#ifdef ENABLE_APPLICATION_BUNDLE
    /*
     * If we're running from an app bundle and weren't started
     * with special privileges, use the Contents/Resources/share/wireshark
     * subdirectory of the app bundle.
     *
     * (appbundle_dir is not set to a non-null value if we're
     * started with special privileges, so we need only check
     * it; we don't need to call started_with_special_privs().)
     */
    else if (appbundle_dir != NULL) {
        datafile_dir = ws_strdup_printf("%s/Contents/Resources/share/%s",
                                        appbundle_dir, CONFIGURATION_NAMESPACE_LOWER);
    }
#endif
    else if (running_in_build_directory_flag && progfile_dir != NULL) {
        /*
         * We're (probably) being run from the build directory and
         * weren't started with special privileges.
         *
         * (running_in_build_directory_flag is never set to true
         * if we're started with special privileges, so we need
         * only check it; we don't need to call started_with_special_privs().)
         *
         * Data files (dtds/, radius/, etc.) are copied to the build
         * directory during the build which also contains executables. A special
         * exception is macOS (when built with an app bundle).
         */
        datafile_dir = g_strdup(progfile_dir);
    } else {
        datafile_dir = g_build_filename(install_prefix, DATA_DIR, CONFIGURATION_NAMESPACE_LOWER, (char *)NULL);
    }
#endif
    return datafile_dir;
}

const char *
get_doc_dir(void)
{
    if (doc_dir != NULL)
        return doc_dir;

    /* No environment variable for this. */
    if (false) {
        ;
    }

#if defined(HAVE_MSYSTEM)
    if (running_in_build_directory_flag) {
        doc_dir = g_strdup(install_prefix);
    } else {
        doc_dir = g_build_filename(install_prefix, DOC_DIR, (char *)NULL);
    }
#elif defined(_WIN32)
    if (progfile_dir != NULL) {
        doc_dir = g_strdup(progfile_dir);
    } else {
        /* Fall back on the default installation directory. */
        doc_dir = g_strdup("C:\\Program Files\\Wireshark\\");
    }
#else
#ifdef ENABLE_APPLICATION_BUNDLE
    /*
     * If we're running from an app bundle and weren't started
     * with special privileges, use the Contents/Resources/share/wireshark
     * subdirectory of the app bundle.
     *
     * (appbundle_dir is not set to a non-null value if we're
     * started with special privileges, so we need only check
     * it; we don't need to call started_with_special_privs().)
     */
    else if (appbundle_dir != NULL) {
        doc_dir = g_strdup(get_datafile_dir());
    }
#endif
    else if (running_in_build_directory_flag && progfile_dir != NULL) {
        /*
         * We're (probably) being run from the build directory and
         * weren't started with special privileges.
         */
        doc_dir = g_strdup(progfile_dir);
    } else {
        doc_dir = g_build_filename(install_prefix, DOC_DIR, (char *)NULL);
    }
#endif
    return doc_dir;
}

/*
 * Find the directory where the plugins are stored.
 *
 * On Windows, we use the plugin\{VERSION} subdirectory of the datafile
 * directory, where {VERSION} is the version number of this version of
 * Wireshark.
 *
 * On UN*X:
 *
 *    if we appear to be run from the build directory, we use the
 *    "plugin" subdirectory of the datafile directory;
 *
 *    otherwise, if the WIRESHARK_PLUGIN_DIR environment variable is
 *    set and we aren't running with special privileges, we use the
 *    value of that environment variable;
 *
 *    otherwise, if we're running from an app bundle in macOS, we
 *    use the Contents/PlugIns/wireshark subdirectory of the app bundle;
 *
 *    otherwise, we use the PLUGIN_DIR value supplied by the
 *    configure script.
 */
static char *plugin_dir;
static char *plugin_dir_with_version;
static char *plugin_pers_dir;
static char *plugin_pers_dir_with_version;
static char *extcap_pers_dir;

static void
init_plugin_dir(void)
{
    const char *plugin_dir_envar = CONFIGURATION_ENVIRONMENT_VARIABLE("PLUGIN_DIR");
    if (g_getenv(plugin_dir_envar) && !started_with_special_privs()) {
        /*
         * The user specified a different directory for plugins
         * and we aren't running with special privileges.
         * Let {WIRESHARK,LOGRAY}_PLUGIN_DIR take precedence.
         */
        plugin_dir = g_strdup(g_getenv(plugin_dir_envar));
    }

#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
#if defined(HAVE_MSYSTEM)
    else if (running_in_build_directory_flag) {
        plugin_dir = g_build_filename(install_prefix, "plugins", (char *)NULL);
    } else {
        plugin_dir = g_build_filename(install_prefix, PLUGIN_DIR, (char *)NULL);
    }
#elif defined(_WIN32)
    else {
        /*
         * On Windows, plugins are stored under the program file directory
         * in both the build and the installation directories.
         */
        plugin_dir = g_build_filename(get_progfile_dir(), "plugins", (char *)NULL);
    }
#else
#ifdef ENABLE_APPLICATION_BUNDLE
    /*
     * If we're running from an app bundle and weren't started
     * with special privileges, use the Contents/PlugIns/wireshark
     * subdirectory of the app bundle.
     *
     * (appbundle_dir is not set to a non-null value if we're
     * started with special privileges, so we need only check
     * it; we don't need to call started_with_special_privs().)
     */
    else if (appbundle_dir != NULL) {
        plugin_dir = g_build_filename(appbundle_dir, "Contents/PlugIns",
                                        CONFIGURATION_NAMESPACE_LOWER, (char *)NULL);
    }
#endif // ENABLE_APPLICATION_BUNDLE
    else if (running_in_build_directory_flag) {
        /*
         * We're (probably) being run from the build directory and
         * weren't started with special privileges, so we'll use
         * the "plugins" subdirectory of the directory where the program
         * we're running is (that's the build directory).
         */
        plugin_dir = g_build_filename(get_progfile_dir(), "plugins", (char *)NULL);
    } else {
        plugin_dir = g_build_filename(install_prefix, PLUGIN_DIR, (char *)NULL);
    }
#endif // HAVE_MSYSTEM / _WIN32
#endif /* defined(HAVE_PLUGINS) || defined(HAVE_LUA) */
}

static void
init_plugin_pers_dir(void)
{
#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
#ifdef _WIN32
    plugin_pers_dir = get_persconffile_path(PLUGINS_DIR_NAME, false);
#else
    plugin_pers_dir = g_build_filename(g_get_home_dir(), ".local/lib",
                                       CONFIGURATION_NAMESPACE_LOWER, PLUGINS_DIR_NAME, (char *)NULL);
#endif
#endif /* defined(HAVE_PLUGINS) || defined(HAVE_LUA) */
}

/*
 * Get the directory in which the plugins are stored.
 */
const char *
get_plugins_dir(void)
{
    if (!plugin_dir)
        init_plugin_dir();
    return plugin_dir;
}

const char *
get_plugins_dir_with_version(void)
{
    if (!plugin_dir)
        init_plugin_dir();
    if (plugin_dir && !plugin_dir_with_version)
        plugin_dir_with_version = g_build_filename(plugin_dir, PLUGIN_PATH_ID, (char *)NULL);
    return plugin_dir_with_version;
}

/* Get the personal plugin dir */
const char *
get_plugins_pers_dir(void)
{
    if (!plugin_pers_dir)
        init_plugin_pers_dir();
    return plugin_pers_dir;
}

const char *
get_plugins_pers_dir_with_version(void)
{
    if (!plugin_pers_dir)
        init_plugin_pers_dir();
    if (plugin_pers_dir && !plugin_pers_dir_with_version)
        plugin_pers_dir_with_version = g_build_filename(plugin_pers_dir, PLUGIN_PATH_ID, (char *)NULL);
    return plugin_pers_dir_with_version;
}

/*
 * Find the directory where the extcap hooks are stored.
 *
 * If the WIRESHARK_EXTCAP_DIR environment variable is set and we are not
 * running with special privileges, use that. Otherwise:
 *
 * On Windows, we use the "extcap" subdirectory of the program directory.
 *
 * On UN*X:
 *
 *    if we appear to be run from the build directory, we use the
 *    "extcap" subdirectory of the build directory.
 *
 *    otherwise, if we're running from an app bundle in macOS, we
 *    use the Contents/MacOS/extcap subdirectory of the app bundle;
 *
 *    otherwise, we use the EXTCAP_DIR value supplied by CMake.
 */
static char *extcap_dir;

static void
init_extcap_dir(void)
{
    const char *extcap_dir_envar = CONFIGURATION_ENVIRONMENT_VARIABLE("EXTCAP_DIR");
    if (g_getenv(extcap_dir_envar) && !started_with_special_privs()) {
        /*
         * The user specified a different directory for extcap hooks
         * and we aren't running with special privileges.
         */
        extcap_dir = g_strdup(g_getenv(extcap_dir_envar));
    }

#if defined(HAVE_MSYSTEM)
    else if (running_in_build_directory_flag) {
        extcap_dir = g_build_filename(install_prefix, "extcap", (char *)NULL);
    } else {
        extcap_dir = g_build_filename(install_prefix, EXTCAP_DIR, (char *)NULL);
    }
#elif defined(_WIN32)
    else {
        /*
         * On Windows, extcap utilities are stored in "extcap/<program name>"
         * in the program file directory in both the build and installation
         * directories.
         */
        extcap_dir = g_build_filename(get_progfile_dir(), EXTCAP_DIR_NAME,
            CONFIGURATION_NAMESPACE_LOWER, (char *)NULL);
    }
#else
#ifdef ENABLE_APPLICATION_BUNDLE
    else if (appbundle_dir != NULL) {
        /*
         * If we're running from an app bundle and weren't started
         * with special privileges, use the Contents/MacOS/extcap
         * subdirectory of the app bundle.
         *
         * (appbundle_dir is not set to a non-null value if we're
         * started with special privileges, so we need only check
         * it; we don't need to call started_with_special_privs().)
         */
        extcap_dir = g_build_filename(appbundle_dir, "Contents/MacOS/extcap", (char *)NULL);
    }
#endif // ENABLE_APPLICATION_BUNDLE
    else if (running_in_build_directory_flag) {
        /*
         * We're (probably) being run from the build directory and
         * weren't started with special privileges, so we'll use
         * the "extcap hooks" subdirectory of the directory where the program
         * we're running is (that's the build directory).
         */
        extcap_dir = g_build_filename(get_progfile_dir(), EXTCAP_DIR_NAME,
            CONFIGURATION_NAMESPACE_LOWER, (char *)NULL);
    }
    else {
        extcap_dir = g_build_filename(install_prefix,
            is_packet_configuration_namespace() ? EXTCAP_DIR : LOG_EXTCAP_DIR, (char *)NULL);
    }
#endif // HAVE_MSYSTEM / _WIN32
}

static void
init_extcap_pers_dir(void)
{
#ifdef _WIN32
    extcap_pers_dir = get_persconffile_path(EXTCAP_DIR_NAME, false);
#else
    extcap_pers_dir = g_build_filename(g_get_home_dir(), ".local/lib",
                                       CONFIGURATION_NAMESPACE_LOWER, EXTCAP_DIR_NAME, (char *)NULL);
#endif
}

/*
 * Get the directory in which the extcap hooks are stored.
 *
 */
const char *
get_extcap_dir(void)
{
    if (!extcap_dir)
        init_extcap_dir();
    return extcap_dir;
}

/* Get the personal plugin dir */
const char *
get_extcap_pers_dir(void)
{
    if (!extcap_pers_dir)
        init_extcap_pers_dir();
    return extcap_pers_dir;
}

/*
 * Get the flag indicating whether we're running from a build
 * directory.
 */
bool
running_in_build_directory(void)
{
    return running_in_build_directory_flag;
}

/*
 * Get the directory in which files that, at least on UNIX, are
 * system files (such as "/etc/ethers") are stored; on Windows,
 * there's no "/etc" directory, so we get them from the global
 * configuration and data file directory.
 */
const char *
get_systemfile_dir(void)
{
#ifdef _WIN32
    return get_datafile_dir();
#else
    return "/etc";
#endif
}

void
set_profile_name(const char *profilename)
{
    g_free (persconfprofile);

    if (profilename && strlen(profilename) > 0 &&
        strcmp(profilename, DEFAULT_PROFILE) != 0) {
        persconfprofile = g_strdup (profilename);
    } else {
        /* Default Profile */
        persconfprofile = NULL;
    }
}

const char *
get_profile_name(void)
{
    if (persconfprofile) {
        return persconfprofile;
    } else {
        return DEFAULT_PROFILE;
    }
}

bool
is_default_profile(void)
{
    return (!persconfprofile || strcmp(persconfprofile, DEFAULT_PROFILE) == 0) ? true : false;
}

bool
has_global_profiles(void)
{
    WS_DIR *dir;
    WS_DIRENT *file;
    char *global_dir = get_global_profiles_dir();
    char *filename;
    bool has_global = false;

    if ((test_for_directory(global_dir) == EISDIR) &&
        ((dir = ws_dir_open(global_dir, 0, NULL)) != NULL))
    {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = ws_strdup_printf ("%s%s%s", global_dir, G_DIR_SEPARATOR_S,
                            ws_dir_get_name(file));
            if (test_for_directory(filename) == EISDIR) {
                has_global = true;
                g_free (filename);
                break;
            }
            g_free (filename);
        }
        ws_dir_close(dir);
    }
    g_free(global_dir);
    return has_global;
}

void
profile_store_persconffiles(bool store)
{
    if (store) {
        profile_files = g_hash_table_new (g_str_hash, g_str_equal);
    }
    do_store_persconffiles = store;
}

void
profile_register_persconffile(const char *filename)
{
    if (do_store_persconffiles && !g_hash_table_lookup (profile_files, filename)) {
        /* Store filenames so we know which filenames belongs to a configuration profile */
        g_hash_table_insert (profile_files, g_strdup(filename), g_strdup(filename));
    }
}

/*
 * Get the directory in which personal configuration files reside.
 *
 * On Windows, it's "Wireshark", under %APPDATA% or, if %APPDATA% isn't set,
 * it's "%USERPROFILE%\Application Data" (which is what %APPDATA% normally
 * is on Windows 2000).
 *
 * On UNIX-compatible systems, we first look in XDG_CONFIG_HOME/wireshark
 * and, if that doesn't exist, ~/.wireshark, for backwards compatibility.
 * If neither exists, we use XDG_CONFIG_HOME/wireshark, so that the directory
 * is initially created as XDG_CONFIG_HOME/wireshark.  We use that regardless
 * of whether the user is running under an XDG desktop or not, so that
 * if the user's home directory is on a server and shared between
 * different desktop environments on different machines, they can all
 * share the same configuration file directory.
 *
 * XXX - what about stuff that shouldn't be shared between machines,
 * such as plugins in the form of shared loadable images?
 */
static const char *
get_persconffile_dir_no_profile(void)
{
    const char *env;

    /* Return the cached value, if available */
    if (persconffile_dir != NULL)
        return persconffile_dir;

    /*
     * See if the user has selected an alternate environment.
     */
    const char *config_dir_envar = CONFIGURATION_ENVIRONMENT_VARIABLE("CONFIG_DIR");
    env = g_getenv(config_dir_envar);
#ifdef _WIN32
    if (env == NULL) {
        /* for backward compatibility */
        env = g_getenv("WIRESHARK_APPDATA");
    }
#endif
    if (env != NULL) {
        persconffile_dir = g_strdup(env);
        return persconffile_dir;
    }

#ifdef _WIN32
    /*
     * Use %APPDATA% or %USERPROFILE%, so that configuration
     * files are stored in the user profile, rather than in
     * the home directory.  The Windows convention is to store
     * configuration information in the user profile, and doing
     * so means you can use Wireshark even if the home directory
     * is an inaccessible network drive.
     */
    env = g_getenv("APPDATA");
    const char *persconf_namespace = CONFIGURATION_NAMESPACE_PROPER;
    if (env != NULL) {
        /*
         * Concatenate %APPDATA% with "\Wireshark" or "\Logray".
         */
        persconffile_dir = g_build_filename(env, persconf_namespace, NULL);
        return persconffile_dir;
    }

    /*
     * OK, %APPDATA% wasn't set, so use %USERPROFILE%\Application Data.
     */
    env = g_getenv("USERPROFILE");
    if (env != NULL) {
        persconffile_dir = g_build_filename(env, "Application Data", persconf_namespace, NULL);
        return persconffile_dir;
    }

    /*
     * Give up and use "C:".
     */
    persconffile_dir = g_build_filename("C:", persconf_namespace, NULL);
    return persconffile_dir;
#else
    char *xdg_path, *path;
    struct passwd *pwd;
    const char *homedir;

    /*
     * Check if XDG_CONFIG_HOME/wireshark exists and is a directory.
     */
    xdg_path = g_build_filename(g_get_user_config_dir(),
                                CONFIGURATION_NAMESPACE_LOWER, NULL);
    if (g_file_test(xdg_path, G_FILE_TEST_IS_DIR)) {
        persconffile_dir = xdg_path;
        return persconffile_dir;
    }

    /*
     * It doesn't exist, or it does but isn't a directory, so try
     * ~/.wireshark.
     *
     * If $HOME is set, use that for ~.
     *
     * (Note: before GLib 2.36, g_get_home_dir() didn't look at $HOME,
     * but we always want to do so, so we don't use g_get_home_dir().)
     */
    homedir = g_getenv("HOME");
    if (homedir == NULL) {
        /*
         * It's not set.
         *
         * Get their home directory from the password file.
         * If we can't even find a password file entry for them,
         * use "/tmp".
         */
        pwd = getpwuid(getuid());
        if (pwd != NULL) {
            homedir = pwd->pw_dir;
        } else {
            homedir = "/tmp";
        }
    }
    path = g_build_filename(homedir,
                            configuration_namespace == CONFIGURATION_NAMESPACE_WIRESHARK ? ".wireshark" : ".logray",
                            NULL);
    if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
        g_free(xdg_path);
        persconffile_dir = path;
        return persconffile_dir;
    }

    /*
     * Neither are directories that exist; use the XDG path, so we'll
     * create that as necessary.
     */
    g_free(path);
    persconffile_dir = xdg_path;
    return persconffile_dir;
#endif
}

void
set_persconffile_dir(const char *p)
{
    g_free(persconffile_dir);
    persconffile_dir = g_strdup(p);
}

char *
get_profiles_dir(void)
{
    return ws_strdup_printf ("%s%s%s", get_persconffile_dir_no_profile (),
                    G_DIR_SEPARATOR_S, PROFILES_DIR);
}

int
create_profiles_dir(char **pf_dir_path_return)
{
    char *pf_dir_path;
    ws_statb64 s_buf;

    /*
     * Create the "Default" personal configuration files directory, if necessary.
     */
    if (create_persconffile_profile (NULL, pf_dir_path_return) == -1) {
        return -1;
    }

    /*
     * Check if profiles directory exists.
     * If not then create it.
     */
    pf_dir_path = get_profiles_dir ();
    if (ws_stat64(pf_dir_path, &s_buf) != 0) {
        if (errno != ENOENT) {
            /* Some other problem; give up now. */
            *pf_dir_path_return = pf_dir_path;
            return -1;
        }

        /*
         * It doesn't exist; try to create it.
         */
        int ret = ws_mkdir(pf_dir_path, 0755);
        if (ret == -1) {
            *pf_dir_path_return = pf_dir_path;
            return ret;
        }
    }
    g_free(pf_dir_path);

    return 0;
}

char *
get_global_profiles_dir(void)
{
    return ws_strdup_printf ("%s%s%s", get_datafile_dir(),
                               G_DIR_SEPARATOR_S, PROFILES_DIR);
}

static char *
get_persconffile_dir(const char *profilename)
{
    char *persconffile_profile_dir = NULL, *profile_dir;

    if (profilename && strlen(profilename) > 0 &&
        strcmp(profilename, DEFAULT_PROFILE) != 0) {
      profile_dir = get_profiles_dir();
      persconffile_profile_dir = ws_strdup_printf ("%s%s%s", profile_dir,
                              G_DIR_SEPARATOR_S, profilename);
      g_free(profile_dir);
    } else {
      persconffile_profile_dir = g_strdup (get_persconffile_dir_no_profile ());
    }

    return persconffile_profile_dir;
}

char *
get_profile_dir(const char *profilename, bool is_global)
{
    char *profile_dir;

    if (is_global) {
        if (profilename && strlen(profilename) > 0 &&
            strcmp(profilename, DEFAULT_PROFILE) != 0)
        {
            char *global_path = get_global_profiles_dir();
            profile_dir = g_build_filename(global_path, profilename, NULL);
            g_free(global_path);
        } else {
            profile_dir = g_strdup(get_datafile_dir());
        }
    } else {
        /*
         * If we didn't supply a profile name, i.e. if profilename is
         * null, get_persconffile_dir() returns the default profile.
         */
        profile_dir = get_persconffile_dir(profilename);
    }

    return profile_dir;
}

bool
profile_exists(const char *profilename, bool global)
{
    char *path = NULL;
    bool exists;

    /*
     * If we're looking up a global profile, we must have a
     * profile name.
     */
    if (global && !profilename)
        return false;

    path = get_profile_dir(profilename, global);
    exists = (test_for_directory(path) == EISDIR) ? true : false;

    g_free(path);
    return exists;
}

static int
delete_directory (const char *directory, char **pf_dir_path_return)
{
    WS_DIR *dir;
    WS_DIRENT *file;
    char *filename;
    int ret = 0;

    if ((dir = ws_dir_open(directory, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = ws_strdup_printf ("%s%s%s", directory, G_DIR_SEPARATOR_S,
                            ws_dir_get_name(file));
            if (test_for_directory(filename) != EISDIR) {
                ret = ws_remove(filename);
#if 0
            } else {
                /* The user has manually created a directory in the profile directory */
                /* I do not want to delete the directory recursively yet */
                ret = delete_directory (filename, pf_dir_path_return);
#endif
            }
            if (ret != 0) {
                *pf_dir_path_return = filename;
                break;
            }
            g_free (filename);
        }
        ws_dir_close(dir);
    }

    if (ret == 0 && (ret = ws_remove(directory)) != 0) {
        *pf_dir_path_return = g_strdup (directory);
    }

    return ret;
}

/* Copy files from one directory to another. Does not recursively copy directories */
static int
copy_directory(const char *from_dir, const char *to_dir, char **pf_filename_return)
{
    int ret = 0;
    char *from_file, *to_file;
    const char *filename;
    WS_DIR *dir;
    WS_DIRENT *file;

    if ((dir = ws_dir_open(from_dir, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            filename = ws_dir_get_name(file);
            from_file = ws_strdup_printf ("%s%s%s", from_dir, G_DIR_SEPARATOR_S, filename);
            if (test_for_directory(from_file) != EISDIR) {
                to_file =  ws_strdup_printf ("%s%s%s", to_dir, G_DIR_SEPARATOR_S, filename);
                if (!copy_file_binary_mode(from_file, to_file)) {
                    *pf_filename_return = g_strdup(filename);
                    g_free (from_file);
                    g_free (to_file);
                    ret = -1;
                    break;
                }
                g_free (to_file);
#if 0
            } else {
                /* The user has manually created a directory in the profile
                 * directory. Do not copy the directory recursively (yet?)
                 */
#endif
            }
            g_free (from_file);
        }
        ws_dir_close(dir);
    }

    return ret;
}

static int
reset_default_profile(char **pf_dir_path_return)
{
    char *profile_dir = get_persconffile_dir(NULL);
    char *filename, *del_file;
    GList *files, *file;
    int ret = 0;

    files = g_hash_table_get_keys(profile_files);
    file = g_list_first(files);
    while (file) {
        filename = (char *)file->data;
        del_file = ws_strdup_printf("%s%s%s", profile_dir, G_DIR_SEPARATOR_S, filename);

        if (file_exists(del_file)) {
            ret = ws_remove(del_file);
            if (ret != 0) {
                *pf_dir_path_return = profile_dir;
                g_free(del_file);
                break;
            }
        }

        g_free(del_file);
        file = g_list_next(file);
    }
    g_list_free(files);

    g_free(profile_dir);
    return ret;
}

int
delete_persconffile_profile(const char *profilename, char **pf_dir_path_return)
{
    if (strcmp(profilename, DEFAULT_PROFILE) == 0) {
        return reset_default_profile(pf_dir_path_return);
    }

    char *profile_dir = get_persconffile_dir(profilename);
    int ret = 0;

    if (test_for_directory (profile_dir) == EISDIR) {
        ret = delete_directory (profile_dir, pf_dir_path_return);
    }

    g_free(profile_dir);
    return ret;
}

int
rename_persconffile_profile(const char *fromname, const char *toname,
                char **pf_from_dir_path_return, char **pf_to_dir_path_return)
{
    char *from_dir = get_persconffile_dir(fromname);
    char *to_dir = get_persconffile_dir(toname);
    int ret = 0;

    ret = ws_rename (from_dir, to_dir);
    if (ret != 0) {
        *pf_from_dir_path_return = from_dir;
        *pf_to_dir_path_return = to_dir;
        return ret;
    }

    g_free (from_dir);
    g_free (to_dir);

    return 0;
}

/*
 * Create the directory that holds personal configuration files, if
 * necessary.  If we attempted to create it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory we failed
 * to create (it's g_mallocated, so our caller should free it); otherwise,
 * return 0.
 */
int
create_persconffile_profile(const char *profilename, char **pf_dir_path_return)
{
    char *pf_dir_path;
#ifdef _WIN32
    char *pf_dir_path_copy, *pf_dir_parent_path;
    size_t pf_dir_parent_path_len;
    int save_errno;
#endif
    ws_statb64 s_buf;
    int ret;

    if (profilename) {
        /*
         * Create the personal profiles directory, if necessary.
         */
        if (create_profiles_dir(pf_dir_path_return) == -1) {
            return -1;
        }
    }

    pf_dir_path = get_persconffile_dir(profilename);
    if (ws_stat64(pf_dir_path, &s_buf) != 0) {
        if (errno != ENOENT) {
            /* Some other problem; give up now. */
            *pf_dir_path_return = pf_dir_path;
            return -1;
        }
#ifdef _WIN32
        /*
         * Does the parent directory of that directory
         * exist?  %APPDATA% may not exist even though
         * %USERPROFILE% does.
         *
         * We check for the existence of the directory
         * by first checking whether the parent directory
         * is just a drive letter and, if it's not, by
         * doing a "stat()" on it.  If it's a drive letter,
         * or if the "stat()" succeeds, we assume it exists.
         */
        pf_dir_path_copy = g_strdup(pf_dir_path);
        pf_dir_parent_path = get_dirname(pf_dir_path_copy);
        pf_dir_parent_path_len = strlen(pf_dir_parent_path);
        if (pf_dir_parent_path_len > 0
            && pf_dir_parent_path[pf_dir_parent_path_len - 1] != ':'
            && ws_stat64(pf_dir_parent_path, &s_buf) != 0) {
            /*
             * Not a drive letter and the stat() failed.
             */
            if (errno != ENOENT) {
                /* Some other problem; give up now. */
                *pf_dir_path_return = pf_dir_path;
                save_errno = errno;
                g_free(pf_dir_path_copy);
                errno = save_errno;
                return -1;
            }
            /*
             * No, it doesn't exist - make it first.
             */
            ret = ws_mkdir(pf_dir_parent_path, 0755);
            if (ret == -1) {
                *pf_dir_path_return = pf_dir_parent_path;
                save_errno = errno;
                g_free(pf_dir_path);
                errno = save_errno;
                return -1;
            }
        }
        g_free(pf_dir_path_copy);
        ret = ws_mkdir(pf_dir_path, 0755);
#else
        ret = g_mkdir_with_parents(pf_dir_path, 0755);
#endif
    } else {
        /*
         * Something with that pathname exists; if it's not
         * a directory, we'll get an error if we try to put
         * something in it, so we don't fail here, we wait
         * for that attempt to fail.
         */
        ret = 0;
    }
    if (ret == -1)
        *pf_dir_path_return = pf_dir_path;
    else
        g_free(pf_dir_path);

    return ret;
}

const GHashTable *
allowed_profile_filenames(void)
{
    return profile_files;
}

int
create_persconffile_dir(char **pf_dir_path_return)
{
    return create_persconffile_profile(persconfprofile, pf_dir_path_return);
}

int
copy_persconffile_profile(const char *toname, const char *fromname, bool from_global,
              char **pf_filename_return, char **pf_to_dir_path_return, char **pf_from_dir_path_return)
{
    int ret = 0;
    char *from_dir;
    char *to_dir = get_persconffile_dir(toname);
    char *from_file, *to_file;
    const char *filename;
    GHashTableIter files;
    void * file;

    from_dir = get_profile_dir(fromname, from_global);

    if (!profile_files || do_store_persconffiles) {
        /* Either the profile_files hashtable does not exist yet
         * (this is very early in startup) or we are still adding
         * files to it. Just copy all the non-directories.
         */
        ret = copy_directory(from_dir, to_dir, pf_filename_return);
    } else {

        g_hash_table_iter_init(&files, profile_files);
        while (g_hash_table_iter_next(&files, &file, NULL)) {
            filename = (const char *)file;
            from_file = ws_strdup_printf ("%s%s%s", from_dir, G_DIR_SEPARATOR_S, filename);
            to_file = ws_strdup_printf ("%s%s%s", to_dir, G_DIR_SEPARATOR_S, filename);

            if (test_for_regular_file(from_file) && !copy_file_binary_mode(from_file, to_file)) {
                *pf_filename_return = g_strdup(filename);
                g_free (from_file);
                g_free (to_file);
                ret = -1;
                break;
            }

            g_free (to_file);
            g_free (from_file);
        }
    }

    if (ret != 0) {
        *pf_to_dir_path_return = to_dir;
        *pf_from_dir_path_return = from_dir;
    } else {
        g_free (to_dir);
        g_free (from_dir);
    }

    return ret;
}

/*
 * Get the (default) directory in which personal data is stored.
 *
 * On Win32, this is the "My Documents" folder in the personal profile.
 * On UNIX this is simply the current directory, unless that's "/",
 * which it will be, for example, when Wireshark is run from the
 * Finder in macOS, in which case we use the user's home directory.
 */
/* XXX - should this and the get_home_dir() be merged? */
extern const char *
get_persdatafile_dir(void)
{
    /* Return the cached value, if available */
    if (persdatafile_dir != NULL)
        return persdatafile_dir;

#ifdef _WIN32
    TCHAR tszPath[MAX_PATH];

    /*
     * Hint: SHGetFolderPath is not available on MSVC 6 - without
     * Platform SDK
     */
    if (SHGetSpecialFolderPath(NULL, tszPath, CSIDL_PERSONAL, false)) {
        persdatafile_dir = g_utf16_to_utf8(tszPath, -1, NULL, NULL, NULL);
        return persdatafile_dir;
    } else {
        return "";
    }
#else
    /*
     * Get the current directory.
     */
    persdatafile_dir = g_get_current_dir();
    if (persdatafile_dir == NULL) {
      /* XXX - can this fail? */
      /*
       * g_get_home_dir() returns a const gchar *; g_strdup() it
       * so that it's something that can be freed.
       */
      persdatafile_dir = g_strdup(g_get_home_dir());
    } else if (strcmp(persdatafile_dir, "/") == 0) {
        g_free(persdatafile_dir);
        /*
         * See above.
         */
        persdatafile_dir = g_strdup(g_get_home_dir());
    }
    return persdatafile_dir;
#endif
}

void
set_persdatafile_dir(const char *p)
{
    g_free(persdatafile_dir);
    persdatafile_dir = g_strdup(p);
}

/*
 * Construct the path name of a personal configuration file, given the
 * file name.
 *
 * On Win32, if "for_writing" is false, we check whether the file exists
 * and, if not, construct a path name relative to the ".wireshark"
 * subdirectory of the user's home directory, and check whether that
 * exists; if it does, we return that, so that configuration files
 * from earlier versions can be read.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
char *
get_persconffile_path(const char *filename, bool from_profile)
{
    char *path, *dir = NULL;

    if (from_profile) {
        /* Store filenames so we know which filenames belongs to a configuration profile */
        profile_register_persconffile(filename);

        dir = get_persconffile_dir(persconfprofile);
    } else {
        dir = get_persconffile_dir(NULL);
    }
    path = g_build_filename(dir, filename, NULL);

    g_free(dir);
    return path;
}

/*
 * Construct the path name of a global configuration file, given the
 * file name.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
char *
get_datafile_path(const char *filename)
{
    if (running_in_build_directory_flag && !strcmp(filename, "hosts")) {
        /* We're running in the build directory and the requested file is a
         * generated (or a test) file.  Return the file name in the build
         * directory (not in the source/data directory).
         * (Oh the things we do to keep the source directory pristine...)
         */
        return g_build_filename(get_progfile_dir(), filename, (char *)NULL);
    } else {
        return g_build_filename(get_datafile_dir(), filename, (char *)NULL);
    }
}

/*
 * Construct the path name of a global documentation file, given the
 * file name.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
char *
get_docfile_path(const char *filename)
{
    if (running_in_build_directory_flag) {
        /* We're running in the build directory and the requested file is a
         * generated (or a test) file.  Return the file name in the build
         * directory (not in the source/data directory).
         * (Oh the things we do to keep the source directory pristine...)
         */
        return g_build_filename(get_progfile_dir(), filename, (char *)NULL);
    } else {
        return g_build_filename(get_doc_dir(), filename, (char *)NULL);
    }
}

/*
 * Return an error message for UNIX-style errno indications on open or
 * create operations.
 */
const char *
file_open_error_message(int err, bool for_writing)
{
    const char *errmsg;
    static char errmsg_errno[1024+1];

    switch (err) {

    case ENOENT:
        if (for_writing)
            errmsg = "The path to the file \"%s\" doesn't exist.";
        else
            errmsg = "The file \"%s\" doesn't exist.";
        break;

    case EACCES:
        if (for_writing)
            errmsg = "You don't have permission to create or write to the file \"%s\".";
        else
            errmsg = "You don't have permission to read the file \"%s\".";
        break;

    case EISDIR:
        errmsg = "\"%s\" is a directory (folder), not a file.";
        break;

    case ENOSPC:
        errmsg = "The file \"%s\" could not be created because there is no space left on the file system.";
        break;

#ifdef EDQUOT
    case EDQUOT:
        errmsg = "The file \"%s\" could not be created because you are too close to, or over, your disk quota.";
        break;
#endif

    case EINVAL:
        errmsg = "The file \"%s\" could not be created because an invalid filename was specified.";
        break;

#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
        /* XXX Make sure we truncate on a character boundary. */
        errmsg = "The file name \"%.80s" UTF8_HORIZONTAL_ELLIPSIS "\" is too long.";
        break;
#endif

    case ENOMEM:
        /*
         * The problem probably has nothing to do with how much RAM the
         * user has on their machine, so don't confuse them by saying
         * "memory".  The problem is probably either virtual address
         * space or swap space.
         */
#if GLIB_SIZEOF_VOID_P == 4
        /*
         * ILP32; we probably ran out of virtual address space.
         */
#define ENOMEM_REASON "it can't be handled by a 32-bit application"
#else
        /*
         * LP64 or LLP64; we probably ran out of swap space.
         */
#if defined(_WIN32)
        /*
         * You need to make the pagefile bigger.
         */
#define ENOMEM_REASON "the pagefile is too small"
#elif defined(ENABLE_APPLICATION_BUNDLE)
        /*
         * dynamic_pager couldn't, or wouldn't, create more swap files.
         */
#define ENOMEM_REASON "your system ran out of swap file space"
#else
        /*
         * Either you have a fixed swap partition or a fixed swap file,
         * and it needs to be made bigger.
         *
         * This is UN*X, but it's not macOS, so we assume the user is
         * *somewhat* nerdy.
         */
#define ENOMEM_REASON "your system is out of swap space"
#endif
#endif /* GLIB_SIZEOF_VOID_P == 4 */
        if (for_writing)
            errmsg = "The file \"%s\" could not be created because " ENOMEM_REASON ".";
        else
            errmsg = "The file \"%s\" could not be opened because " ENOMEM_REASON ".";
        break;

    default:
        snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" could not be %s: %s.",
               for_writing ? "created" : "opened",
               g_strerror(err));
        errmsg = errmsg_errno;
        break;
    }
    return errmsg;
}

/*
 * Return an error message for UNIX-style errno indications on write
 * operations.
 */
const char *
file_write_error_message(int err)
{
    const char *errmsg;
    static char errmsg_errno[1024+1];

    switch (err) {

    case ENOSPC:
        errmsg = "The file \"%s\" could not be saved because there is no space left on the file system.";
        break;

#ifdef EDQUOT
    case EDQUOT:
        errmsg = "The file \"%s\" could not be saved because you are too close to, or over, your disk quota.";
        break;
#endif

    default:
        snprintf(errmsg_errno, sizeof(errmsg_errno),
               "An error occurred while writing to the file \"%%s\": %s.",
               g_strerror(err));
        errmsg = errmsg_errno;
        break;
    }
    return errmsg;
}


bool
file_exists(const char *fname)
{
    ws_statb64 file_stat;

    if (!fname) {
        return false;
    }

    if (ws_stat64(fname, &file_stat) != 0 && errno == ENOENT) {
        return false;
    } else {
        return true;
    }
}

bool config_file_exists_with_entries(const char *fname, char comment_char)
{
    bool start_of_line = true;
    bool has_entries = false;
    FILE *file;
    int c;

    if (!fname) {
        return false;
    }

    if ((file = ws_fopen(fname, "r")) == NULL) {
        return false;
    }

    do {
        c = ws_getc_unlocked(file);
        if (start_of_line && c != comment_char && !g_ascii_isspace(c) && g_ascii_isprint(c)) {
            has_entries = true;
            break;
        }
        if (c == '\n' || !g_ascii_isspace(c)) {
            start_of_line = (c == '\n');
        }
    } while (c != EOF);

    fclose(file);
    return has_entries;
}

/*
 * Check that the from file is not the same as to file
 * We do it here so we catch all cases ...
 * Unfortunately, the file requester gives us an absolute file
 * name and the read file name may be relative (if supplied on
 * the command line), so we can't just compare paths. From Joerg Mayer.
 */
bool
files_identical(const char *fname1, const char *fname2)
{
    /* Two different implementations, because st_ino isn't filled in with
     * a meaningful value on Windows. Use the Windows API and FILE_ID_INFO
     * instead.
     */
#ifdef _WIN32

    FILE_ID_INFO filestat1, filestat2;

    /*
     * Compare VolumeSerialNumber and FileId.
     */

    HANDLE h1 = CreateFile(utf_8to16(fname1), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (h1 == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (!GetFileInformationByHandleEx(h1, FileIdInfo, &filestat1, sizeof(FILE_ID_INFO))) {
        CloseHandle(h1);
        return false;
    }
    CloseHandle(h1);

    HANDLE h2 = CreateFile(utf_8to16(fname2), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (h2 == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (!GetFileInformationByHandleEx(h2, FileIdInfo, &filestat2, sizeof(FILE_ID_INFO))) {
        CloseHandle(h2);
        return false;
    }
    CloseHandle(h2);

    return ((memcmp(&filestat1.FileId, &filestat2.FileId, sizeof(FILE_ID_128)) == 0) &&
        filestat1.VolumeSerialNumber == filestat2.VolumeSerialNumber);
#else
    ws_statb64 filestat1, filestat2;

    /*
     * Compare st_dev and st_ino.
     */
    if (ws_stat64(fname1, &filestat1) == -1)
        return false;   /* can't get info about the first file */
    if (ws_stat64(fname2, &filestat2) == -1)
        return false;   /* can't get info about the second file */
    return (filestat1.st_dev == filestat2.st_dev &&
        filestat1.st_ino == filestat2.st_ino);
#endif
}

bool
file_needs_reopen(int fd, const char* filename)
{
#ifdef _WIN32
    /* Windows handles st_dev in a way unsuitable here:
     *   * _fstat() simply casts the file descriptor (ws_fileno(fp)) to unsigned
     *     and assigns this value to st_dev and st_rdev
     *   * _wstat() converts drive letter (eg. C) to number (A=0, B=1, C=2, ...)
     *     and assigns such number to st_dev and st_rdev
     *
     * The st_ino parameter is simply zero as there is no specific assignment
     * to it in the Universal CRT source code.
     *
     * Thus instead of using fstat(), use Windows specific API.
     */

    HANDLE open_handle = (HANDLE)_get_osfhandle(fd);
    HANDLE current_handle = CreateFile(utf_8to16(filename), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
    BY_HANDLE_FILE_INFORMATION open_info, current_info;

    if (current_handle == INVALID_HANDLE_VALUE) {
        return true;
    }

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
    FILE_ID_INFO open_id, current_id;
    if (GetFileInformationByHandleEx(open_handle, FileIdInfo, &open_id, sizeof(open_id)) &&
        GetFileInformationByHandleEx(current_handle, FileIdInfo, &current_id, sizeof(current_id))) {
        /* 128-bit identifier is available, use it */
        CloseHandle(current_handle);
        return open_id.VolumeSerialNumber != current_id.VolumeSerialNumber ||
               memcmp(&open_id.FileId, &current_id.FileId, sizeof(open_id.FileId)) != 0;
    }
#endif /* _WIN32_WINNT >= _WIN32_WINNT_WIN8 */
    if (GetFileInformationByHandle(open_handle, &open_info) &&
        GetFileInformationByHandle(current_handle, &current_info)) {
        /* Fallback to 64-bit identifier */
        CloseHandle(current_handle);
        uint64_t open_size = (((uint64_t)open_info.nFileSizeHigh) << 32) | open_info.nFileSizeLow;
        uint64_t current_size = (((uint64_t)current_info.nFileSizeHigh) << 32) | current_info.nFileSizeLow;
        return open_info.dwVolumeSerialNumber != current_info.dwVolumeSerialNumber ||
               open_info.nFileIndexHigh != current_info.nFileIndexHigh ||
               open_info.nFileIndexLow != current_info.nFileIndexLow ||
               open_size > current_size;
    }
    CloseHandle(current_handle);
    return true;
#else
    ws_statb64 open_stat, current_stat;

    /* consider a file deleted when stat fails for either file,
     * or when the residing device / inode has changed. */
    if (0 != ws_fstat64(fd, &open_stat))
        return true;
    if (0 != ws_stat64(filename, &current_stat))
        return true;

    return open_stat.st_dev != current_stat.st_dev ||
           open_stat.st_ino != current_stat.st_ino ||
           open_stat.st_size > current_stat.st_size;
#endif
}

bool
write_file_binary_mode(const char *filename, const void *content, size_t content_len)
{
    int fd;
    size_t bytes_left;
    unsigned int bytes_to_write;
    ssize_t bytes_written;
    const uint8_t *ptr;
    int err;

    fd = ws_open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd == -1) {
        report_open_failure(filename, errno, true);
        return false;
    }

    /*
     * The third argument to _write() on Windows is an unsigned int,
     * so, on Windows, that's the size of the third argument to
     * ws_write().
     *
     * The third argument to write() on UN*X is a size_t, although
     * the return value is an ssize_t, so one probably shouldn't
     * write more than the max value of an ssize_t.
     *
     * In either case, there's no guarantee that a size_t such as
     * content_len can be passed to ws_write(), so we write in
     * chunks of at most 2^31 bytes.
     */

    ptr = (const uint8_t *)content;
    bytes_left = content_len;
    while (bytes_left != 0) {
        if (bytes_left > 0x40000000) {
            bytes_to_write = 0x40000000;
        } else {
            bytes_to_write = (unsigned int)bytes_left;
        }
        bytes_written = ws_write(fd, ptr, bytes_to_write);
        if (bytes_written <= 0) {
            if (bytes_written < 0) {
                err = errno;
            } else {
                err = WTAP_ERR_SHORT_WRITE;
            }
            report_write_failure(filename, err);
            ws_close(fd);
            return false;
        }
        bytes_left -= bytes_written;
        ptr += bytes_written;
    }

    ws_close(fd);
    return true;
}

/*
 * Copy a file in binary mode, for those operating systems that care about
 * such things.  This should be OK for all files, even text files, as
 * we'll copy the raw bytes, and we don't look at the bytes as we copy
 * them.
 *
 * Returns true on success, false on failure. If a failure, it also
 * displays a simple dialog window with the error message.
 */
bool
copy_file_binary_mode(const char *from_filename, const char *to_filename)
{
    int           from_fd, to_fd, err;
    ws_file_ssize_t nread, nwritten;
    uint8_t       *pd = NULL;

    /* Copy the raw bytes of the file. */
    from_fd = ws_open(from_filename, O_RDONLY | O_BINARY, 0000 /* no creation so don't matter */);
    if (from_fd < 0) {
        report_open_failure(from_filename, errno, false);
        goto done;
    }

    /* Use open() instead of creat() so that we can pass the O_BINARY
       flag, which is relevant on Win32; it appears that "creat()"
       may open the file in text mode, not binary mode, but we want
       to copy the raw bytes of the file, so we need the output file
       to be open in binary mode. */
    to_fd = ws_open(to_filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (to_fd < 0) {
        report_open_failure(to_filename, errno, true);
        ws_close(from_fd);
        goto done;
    }

#define FS_READ_SIZE 65536
    pd = (uint8_t *)g_malloc(FS_READ_SIZE);
    while ((nread = ws_read(from_fd, pd, FS_READ_SIZE)) > 0) {
        nwritten = ws_write(to_fd, pd, nread);
        if (nwritten < nread) {
            if (nwritten < 0)
                err = errno;
            else
                err = WTAP_ERR_SHORT_WRITE;
            report_write_failure(to_filename, err);
            ws_close(from_fd);
            ws_close(to_fd);
            goto done;
        }
    }
    if (nread < 0) {
        err = errno;
        report_read_failure(from_filename, err);
        ws_close(from_fd);
        ws_close(to_fd);
        goto done;
    }
    ws_close(from_fd);
    if (ws_close(to_fd) < 0) {
        report_write_failure(to_filename, errno);
        goto done;
    }

    g_free(pd);
    pd = NULL;
    return true;

done:
    g_free(pd);
    return false;
}

char *
data_file_url(const char *filename)
{
    char *file_path;
    char *uri;

    /* Absolute path? */
    if(g_path_is_absolute(filename)) {
        file_path = g_strdup(filename);
    } else {
        file_path = ws_strdup_printf("%s/%s", get_datafile_dir(), filename);
    }

    /* XXX - check, if the file is really existing, otherwise display a simple_dialog about the problem */

    /* convert filename to uri */
    uri = g_filename_to_uri(file_path, NULL, NULL);
    g_free(file_path);
    return uri;
}

char *
doc_file_url(const char *filename)
{
    char *file_path;
    char *uri;

    /* Absolute path? */
    if(g_path_is_absolute(filename)) {
        file_path = g_strdup(filename);
    } else {
        file_path = ws_strdup_printf("%s/%s", get_doc_dir(), filename);
    }

    /* XXX - check, if the file is really existing, otherwise display a simple_dialog about the problem */

    /* convert filename to uri */
    uri = g_filename_to_uri(file_path, NULL, NULL);
    g_free(file_path);
    return uri;
}

void
free_progdirs(void)
{
    g_free(persconffile_dir);
    persconffile_dir = NULL;
    g_free(datafile_dir);
    datafile_dir = NULL;
    g_free(persdatafile_dir);
    persdatafile_dir = NULL;
    g_free(persconfprofile);
    persconfprofile = NULL;
    g_free(progfile_dir);
    progfile_dir = NULL;
    g_free(doc_dir);
    doc_dir = NULL;
    g_free(install_prefix);
    install_prefix = NULL;
    g_free(current_working_dir);
    current_working_dir = NULL;
#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
    g_free(plugin_dir);
    plugin_dir = NULL;
    g_free(plugin_dir_with_version);
    plugin_dir_with_version = NULL;
    g_free(plugin_pers_dir);
    plugin_pers_dir = NULL;
    g_free(plugin_pers_dir_with_version);
    plugin_pers_dir_with_version = NULL;
#endif
    g_free(extcap_dir);
    extcap_dir = NULL;
    g_free(extcap_pers_dir);
    extcap_pers_dir = NULL;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
