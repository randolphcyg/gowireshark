/** @file
 * Definitions for routines for merging files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MERGE_H__
#define __MERGE_H__

#include "wiretap/wtap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    RECORD_PRESENT,
    RECORD_NOT_PRESENT,
    AT_EOF,
    GOT_ERROR
} in_file_state_e;

/**
 * Structures to manage our input files.
 */
typedef struct merge_in_file_s {
    const char     *filename;
    wtap           *wth;
    wtap_rec        rec;
    Buffer          frame_buffer;
    in_file_state_e state;
    uint32_t        packet_num;     /* current packet number */
    int64_t         size;           /* file size */
    GArray         *idb_index_map;  /* used for mapping the old phdr interface_id values to new during merge */
    unsigned        nrbs_seen;      /* number of elements processed so far from wth->nrbs */
    unsigned        dsbs_seen;      /* number of elements processed so far from wth->dsbs */
} merge_in_file_t;

/** Merge events, used as an arg in the callback function - indicates when the callback was invoked. */
typedef enum {
    MERGE_EVENT_INPUT_FILES_OPENED,
    MERGE_EVENT_FRAME_TYPE_SELECTED,
    MERGE_EVENT_READY_TO_MERGE,
    MERGE_EVENT_RECORD_WAS_READ,
    MERGE_EVENT_DONE
} merge_event;


/** Merge mode for IDB info. */
typedef enum {
    IDB_MERGE_MODE_NONE = 0,    /**< no merging of IDBs is done, all IDBs are copied into merged file */
    IDB_MERGE_MODE_ALL_SAME,/**< duplicate IDBs merged only if all the files have the same set of IDBs */
    IDB_MERGE_MODE_ANY_SAME, /**< any and all duplicate IDBs are merged into one IDB, even within a file */
    IDB_MERGE_MODE_MAX
} idb_merge_mode;


/** Returns the idb_merge_mode for the given string name.
 *
 * @param name The name of the mode.
 * @return The idb_merge_mode, or IDB_MERGE_MODE_MAX on failure.
 */
WS_DLL_PUBLIC idb_merge_mode
merge_string_to_idb_merge_mode(const char *name);


/** Returns the string name for the given number.
 *
 * @param mode The number of the mode, representing the idb_merge_mode enum value.
 * @return The string name, or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC const char*
merge_idb_merge_mode_to_string(const int mode);


/** @struct merge_progress_callback_t
 *
 * @brief Callback information for merging.
 *
 * @details The merge_files() routine can invoke a callback during its execution,
 * to enable verbose printing or progress bar updating, for example. This struct
 * provides merge_files() with the callback routine to invoke, and optionally
 * private data to pass through to the callback each time it is invoked.
 * For the callback_func routine's arguments: the event is when the callback
 * was invoked, the num is an int specific to the event, in_files is an array
 * of the created merge info, in_file_count is the size of the array, data is
 * whatever was passed in the data member of this struct. The callback_func
 * routine's return value should be true if merging should be aborted.
 */
typedef struct {
    bool (*callback_func)(merge_event event, int num,
                              const merge_in_file_t in_files[], const unsigned in_file_count,
                              void *data);
    void *data; /**< private data to use for passing through to the callback function */
} merge_progress_callback_t;


/** Merge the given input files to a file with the given filename
 *
 * @param out_filename The output filename
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param compression_type The compresion type to use for the output
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files(const char* out_filename, const int file_type,
            const char *const *in_filenames, const unsigned in_file_count,
            const bool do_append, const idb_merge_mode mode,
            unsigned snaplen, const char *app_name, merge_progress_callback_t* cb,
            wtap_compression_type compression_type);

/** Merge the given input files to a temporary file
 *
 * @param tmpdir Points to the directory in which to write the temporary file
 * @param out_filenamep Points to a pointer that's set to point to the
 *        pathname of the temporary file; it's allocated with g_malloc()
 * @param pfx A string to be used as the prefix for the temporary file name
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files_to_tempfile(const char *tmpdir, char **out_filenamep, const char *pfx,
                        const int file_type, const char *const *in_filenames,
                        const unsigned in_file_count, const bool do_append,
                        const idb_merge_mode mode, unsigned snaplen,
                        const char *app_name, merge_progress_callback_t* cb);

/** Merge the given input files to the standard output
 *
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files_to_stdout(const int file_type, const char *const *in_filenames,
                      const unsigned in_file_count, const bool do_append,
                      const idb_merge_mode mode, unsigned snaplen,
                      const char *app_name, merge_progress_callback_t* cb,
                      wtap_compression_type compression_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

