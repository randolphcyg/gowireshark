/* cmakeconfig.h.in */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/* Note: You cannot use earlier #defines in later #cmakedefines (cmake 2.6.2). */

/* Name of package */
#define PACKAGE "wireshark"

#define VERSION_EXTRA ""

/* Version number of Wireshark and associated utilities */
#define VERSION "4.0.10"
#define VERSION_MAJOR 4
#define VERSION_MINOR 0
#define VERSION_MICRO 10

/* Version number of Logray and associated utilities */
#define LOG_VERSION "0.8.10"

#define PLUGIN_PATH_ID "4.0"
#define VERSION_FLAVOR ""

/* Build wsutil with SIMD optimization */
/* #undef HAVE_SSE4_2 */

/* Define to 1 if we want to enable plugins */
#define HAVE_PLUGINS 1

/*  Define to 1 if we check hf conflict */
/* #undef ENABLE_CHECK_FILTER */

/* Link Wireshark libraries statically */
/* #undef ENABLE_STATIC */

/* Enable AirPcap */
/* #undef HAVE_AIRPCAP */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the `clock_gettime` function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the `timespec_get` function. */
#define HAVE_TIMESPEC_GET 1

/* Define to use the MaxMind DB library */
/* #undef HAVE_MAXMINDDB */

/* Define to 1 if you have the <ifaddrs.h> header file. */
#define HAVE_IFADDRS_H 1

/* Define to 1 if yu have the `fseeko` function. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `getexecname' function. */
/* #undef HAVE_GETEXECNAME */

/* Define to 1 if you have the `getifaddrs' function. */
#define HAVE_GETIFADDRS 1

/* Define if LIBSSH support is enabled */
/* #undef HAVE_LIBSSH */

/* Define if you have the 'dlget' function. */
/* #undef HAVE_DLGET */

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to use heimdal kerberos */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define to 1 if you have the `krb5_pac_verify' function. */
/* #undef HAVE_KRB5_PAC_VERIFY */

/* Define to 1 if you have the `krb5_c_fx_cf2_simple' function. */
/* #undef HAVE_KRB5_C_FX_CF2_SIMPLE */

/* Define to 1 if you have the `decode_krb5_enc_tkt_part' function. */
/* #undef HAVE_DECODE_KRB5_ENC_TKT_PART */

/* Define to 1 if you have the `encode_krb5_enc_tkt_part' function. */
/* #undef HAVE_ENCODE_KRB5_ENC_TKT_PART */

/* Define to 1 if you have the `inflatePrime' function. */
#define HAVE_INFLATEPRIME 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to use kerberos */
/* #undef HAVE_KERBEROS */

/* Define to use PCRE2 library */
#define HAVE_PCRE2 1

/* Define to use nghttp2 */
/* #undef HAVE_NGHTTP2 */

/* Define to use the libcap library */
/* #undef HAVE_LIBCAP */

/* Define to use GnuTLS library */
/* #undef HAVE_LIBGNUTLS */

/* Define to 1 if GnuTLS was built with pkcs11 support. */
/* #undef HAVE_GNUTLS_PKCS11 */

/* Enable libnl support */
/* #undef HAVE_LIBNL */

/* libnl version 1 */
/* #undef HAVE_LIBNL1 */

/* libnl version 2 */
/* #undef HAVE_LIBNL2 */

/* libnl version 3 */
/* #undef HAVE_LIBNL3 */

/* Define to use libpcap library */
#define HAVE_LIBPCAP 1

/* Define to 1 if you have the `smi' library (-lsmi). */
/* #undef HAVE_LIBSMI */

/* Define to 1 if libsmi exports a version string (and that symbol is visible). */
/* #undef HAVE_SMI_VERSION_STRING */

/* Define to use zlib library */
#define HAVE_ZLIB 1

/* Define to use the minizip library */
/* #undef HAVE_MINIZIP */

/* Define if `dos_date' (with underscore) field exists in `zip_fileinfo'  */
/* #undef HAVE_MZCOMPAT_DOS_DATE */

/* Define to use brotli library */
/* #undef HAVE_BROTLI */

/* Define to use lz4 library */
/* #undef HAVE_LZ4 */

/* Check for lz4frame */
/* #undef HAVE_LZ4FRAME_H */

/* Define to use snappy library */
/* #undef HAVE_SNAPPY */

/* Define to use zstd library */
/* #undef HAVE_ZSTD */

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the <linux/if_bonding.h> header file. */
#define HAVE_LINUX_IF_BONDING_H 1

/* Define to use Lua */
/* #undef HAVE_LUA */

/* Define to use MIT kerberos */
/* #undef HAVE_MIT_KERBEROS */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* nl80211.h is new enough */
/* #undef HAVE_NL80211 */

/* SET_CHANNEL is supported */
/* #undef HAVE_NL80211_CMD_SET_CHANNEL */

/* SPLIT_WIPHY_DUMP is supported */
/* #undef HAVE_NL80211_SPLIT_WIPHY_DUMP */

/* VHT_CAPABILITY is supported */
/* #undef HAVE_NL80211_VHT_CAPABILITY */

/* Define to 1 if you have macOS frameworks */
/* #undef HAVE_MACOS_FRAMEWORKS */

/* Define to 1 if you have the macOS CFPropertyListCreateWithStream function */
/* #undef HAVE_CFPROPERTYLISTCREATEWITHSTREAM */

/* Define to 1 if you have the `pcap_create' function. */
#define HAVE_PCAP_CREATE 1

/* Define to 1 if the capture buffer size can be set. */
#define CAN_SET_CAPTURE_BUFFER_SIZE 1

/* Define to 1 if you have the `pcap_freecode' function. */
#define HAVE_PCAP_FREECODE 1

/* Define to 1 if you have the `pcap_free_datalinks' function. */
#define HAVE_PCAP_FREE_DATALINKS 1

/* Define to 1 if you have the `pcap_open' function. */
/* #undef HAVE_PCAP_OPEN */

/* Define to 1 if you have libpcap/WinPcap/Npcap remote capturing support. */
/* #undef HAVE_PCAP_REMOTE */

/* Define to 1 if you have the `pcap_setsampling' function. */
/* #undef HAVE_PCAP_SETSAMPLING */

/* Define to 1 if you have the `pcap_set_tstamp_precision' function. */
#define HAVE_PCAP_SET_TSTAMP_PRECISION 1

/* Define to 1 if you have the `pcap_set_tstamp_type' function. */
#define HAVE_PCAP_SET_TSTAMP_TYPE 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you want to playing SBC by standalone BlueZ SBC library */
/* #undef HAVE_SBC */

/* Define to 1 if you have the SpanDSP library. */
/* #undef HAVE_SPANDSP */

/* Define to 1 if you have the bcg729 library. */
/* #undef HAVE_BCG729 */

/* Define to 1 if you have the ilbc library. */
/* #undef HAVE_ILBC */

/* Define to 1 if you have the opus library. */
/* #undef HAVE_OPUS */

/* Define to 1 if you have the speexdsp library. */
/* #undef HAVE_SPEEXDSP */

/* Define to 1 if you have the lixbml2 library. */
/* #undef HAVE_LIBXML2 */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the Sparkle or WinSparkle library */
/* #undef HAVE_SOFTWARE_UPDATE */

/* Define if you have the 'strptime' function. */
#define HAVE_STRPTIME 1

/* Define if you have the 'memmem' function. */
#define HAVE_MEMMEM 1

/* Define if you have the 'strcasestr' function. */
#define HAVE_STRCASESTR 1

/* Define if you have the 'strerrorname_np' function. */
#define HAVE_STRERRORNAME_NP 1

/* Define if you have the 'vasprintf' function. */
#define HAVE_VASPRINTF 1

/* Define to 1 if `st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BIRTHTIME */

/* Define if st_blksize field exists in struct stat */
#define HAVE_STRUCT_STAT_ST_BLKSIZE 1

/* Define to 1 if `__st_birthtime' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT___ST_BIRTHTIME */

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define if tm_zone field exists in struct tm */
#define HAVE_STRUCT_TM_TM_ZONE 1

/* Define if tzname array exists */
#define HAVE_TZNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define if we have QtMultimedia */
/* #undef QT_MULTIMEDIA_LIB */

/* Build androiddump with libpcap instead of wireshark stuff */
/* #undef ANDROIDDUMP_USE_LIBPCAP */

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* Note: not use in the code */
/* #undef YYTEXT_POINTER */

/* Define to 1 if the 'ssize_t' type exists. */
#define HAVE_SSIZE_T 1

#if defined(_MSC_VER)
#  define strncasecmp strnicmp
#  define popen       _popen
#  define pclose      _pclose
#endif

#if defined(_WIN32)
   /*
    * Flex (v 2.5.35) uses this symbol to "exclude" unistd.h
    */
#  define YY_NO_UNISTD_H

#  ifndef __STDC__
#    define __STDC__ 0
#  endif
#endif

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH  8
#endif

#include <include/ws_log_defs.h>

#endif /* __CONFIG_H__ */
