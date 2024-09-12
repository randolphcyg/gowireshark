/* radcom.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "radcom.h"

#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"

struct frame_date {
	uint16_t	year;
	uint8_t	month;
	uint8_t	day;
	uint32_t	sec;		/* seconds since midnight */
	uint32_t	usec;
};

struct unaligned_frame_date {
	char	year[2];
	char	month;
	char	day;
	char	sec[4];		/* seconds since midnight */
	char	usec[4];
};

/* Found at the beginning of the file. Bytes 2 and 3 (D2:00) seem to be
 * different in some captures */
static const uint8_t radcom_magic[8] = {
	0x42, 0xD2, 0x00, 0x34, 0x12, 0x66, 0x22, 0x88
};

static const uint8_t encap_magic[4] = {
	0x00, 0x42, 0x43, 0x09
};

static const uint8_t active_time_magic[11] = {
	'A', 'c', 't', 'i', 'v', 'e', ' ', 'T', 'i', 'm', 'e'
};

/* RADCOM record header - followed by frame data (perhaps including FCS).

   "data_length" appears to be the length of packet data following
   the record header.  It's 0 in the last record.

   "length" appears to be the amount of captured packet data, and
   "real_length" might be the actual length of the frame on the wire -
   in some captures, it's the same as "length", and, in others,
   it's greater than "length".  In the last record, however, those
   may have bogus values (or is that some kind of trailer record?).

   "xxx" appears to be all-zero in all but the last record in one
   capture; if so, perhaps this indicates that the last record is,
   in fact, a trailer of some sort, and some field in the header
   is a record type. */
struct radcomrec_hdr {
	char	xxx[4];		/* unknown */
	char	data_length[2];	/* packet length? */
	char	xxy[5];		/* unknown */
	struct unaligned_frame_date date; /* date/time stamp of packet */
	char	real_length[2];	/* actual length of packet */
	char	length[2];	/* captured length of packet */
	char	xxz[2];		/* unknown */
	char	dce;		/* DCE/DTE flag (and other flags?) */
	char	xxw[9];		/* unknown */
};

static bool radcom_read(wtap *wth, wtap_rec *rec, Buffer *buf,
	int *err, char **err_info, int64_t *data_offset);
static bool radcom_seek_read(wtap *wth, int64_t seek_off,
	wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static bool radcom_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec,
	Buffer *buf, int *err, char **err_info);

static int radcom_file_type_subtype = -1;

void register_radcom(void);

wtap_open_return_val radcom_open(wtap *wth, int *err, char **err_info)
{
	uint8_t r_magic[8], t_magic[11], search_encap[7];
	struct frame_date start_date;
#if 0
	uint32_t sec;
	struct tm tm;
#endif

	/* Read in the string that should be at the start of a RADCOM file */
	if (!wtap_read_bytes(wth->fh, r_magic, 8, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* XXX: bytes 2 and 3 of the "magic" header seem to be different in some
	 * captures. We force them to our standard value so that the test
	 * succeeds (until we find if they have a special meaning, perhaps a
	 * version number ?) */
	r_magic[1] = 0xD2;
	r_magic[2] = 0x00;
	if (memcmp(r_magic, radcom_magic, 8) != 0) {
		return WTAP_OPEN_NOT_MINE;
	}

	/* Look for the "Active Time" string. The "frame_date" structure should
	 * be located 32 bytes before the beginning of this string */
	if (!wtap_read_bytes(wth->fh, t_magic, 11, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}
	while (memcmp(t_magic, active_time_magic, 11) != 0)
	{
		if (file_seek(wth->fh, -10, SEEK_CUR, err) == -1)
			return WTAP_OPEN_ERROR;
		if (!wtap_read_bytes(wth->fh, t_magic, 11, err, err_info)) {
			if (*err != WTAP_ERR_SHORT_READ)
				return WTAP_OPEN_ERROR;
			return WTAP_OPEN_NOT_MINE;
		}
	}
	if (file_seek(wth->fh, -43, SEEK_CUR, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Get capture start time */
	if (!wtap_read_bytes(wth->fh, &start_date, sizeof(struct frame_date),
	    err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* So what time is this? */
	if (!wtap_read_bytes(wth->fh, NULL, sizeof(struct frame_date),
	    err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	for (;;) {
		if (!wtap_read_bytes(wth->fh, search_encap, 4,
		    err, err_info)) {
			if (*err != WTAP_ERR_SHORT_READ)
				return WTAP_OPEN_ERROR;
			return WTAP_OPEN_NOT_MINE;
		}

		if (memcmp(encap_magic, search_encap, 4) == 0)
			break;

		/*
		 * OK, that's not it, go forward 1 byte - reading
		 * the magic moved us forward 4 bytes, so seeking
		 * backward 3 bytes moves forward 1 byte - and
		 * try the 4 bytes at that offset.
		 */
		if (file_seek(wth->fh, -3, SEEK_CUR, err) == -1)
			return WTAP_OPEN_ERROR;
	}
	if (!wtap_read_bytes(wth->fh, NULL, 12, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}
	if (!wtap_read_bytes(wth->fh, search_encap, 4, err, err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/* This is a radcom file */
	wth->file_type_subtype = radcom_file_type_subtype;
	wth->subtype_read = radcom_read;
	wth->subtype_seek_read = radcom_seek_read;
	wth->snapshot_length = 0; /* not available in header, only in frame */
	wth->file_tsprec = WTAP_TSPREC_USEC;

#if 0
	tm.tm_year = pletoh16(&start_date.year)-1900;
	tm.tm_mon = start_date.month-1;
	tm.tm_mday = start_date.day;
	sec = pletoh32(&start_date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;
#endif

	if (memcmp(search_encap, "LAPB", 4) == 0)
		wth->file_encap = WTAP_ENCAP_LAPB;
	else if (memcmp(search_encap, "Ethe", 4) == 0)
		wth->file_encap = WTAP_ENCAP_ETHERNET;
	else if (memcmp(search_encap, "ATM/", 4) == 0)
		wth->file_encap = WTAP_ENCAP_ATM_RFC1483;
	else {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = ws_strdup_printf("radcom: network type \"%.4s\" unknown", search_encap);
		return WTAP_OPEN_ERROR;
	}

#if 0
	if (!wtap_read_bytes(wth->fh, &next_date, sizeof(struct frame_date),
	    err, err_info))
		return WTAP_OPEN_ERROR;

	while (memcmp(&start_date, &next_date, 4)) {
		if (file_seek(wth->fh, 1-sizeof(struct frame_date), SEEK_CUR, err) == -1)
			return WTAP_OPEN_ERROR;
		if (!wtap_read_bytes(wth->fh, &next_date, sizeof(struct frame_date),
		    err, err_info))
			return WTAP_OPEN_ERROR;
	}
#endif

	if (wth->file_encap == WTAP_ENCAP_ETHERNET) {
		if (!wtap_read_bytes(wth->fh, NULL, 294, err, err_info))
			return WTAP_OPEN_ERROR;
	} else if (wth->file_encap == WTAP_ENCAP_LAPB) {
		if (!wtap_read_bytes(wth->fh, NULL, 297, err, err_info))
			return WTAP_OPEN_ERROR;
	} else if (wth->file_encap == WTAP_ENCAP_ATM_RFC1483) {
		if (!wtap_read_bytes(wth->fh, NULL, 504, err, err_info))
			return WTAP_OPEN_ERROR;
	}

	/*
	 * Add an IDB; we don't know how many interfaces were involved,
	 * so we just say one interface, about which we only know
	 * the link-layer type, snapshot length, and time stamp
	 * resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

/* Read the next packet */
static bool radcom_read(wtap *wth, wtap_rec *rec, Buffer *buf,
			    int *err, char **err_info, int64_t *data_offset)
{
	char	fcs[2];

	*data_offset = file_tell(wth->fh);

	/* Read record. */
	if (!radcom_read_rec(wth, wth->fh, rec, buf, err, err_info)) {
		/* Read error or EOF */
		return false;
	}

	if (wth->file_encap == WTAP_ENCAP_LAPB) {
		/* Read the FCS.
		   XXX - should we have some way of indicating the
		   presence and size of an FCS to our caller?
		   That'd let us handle other file types as well. */
		if (!wtap_read_bytes(wth->fh, &fcs, sizeof fcs, err, err_info))
			return false;
	}

	return true;
}

static bool
radcom_seek_read(wtap *wth, int64_t seek_off,
		 wtap_rec *rec, Buffer *buf,
		 int *err, char **err_info)
{
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	/* Read record. */
	if (!radcom_read_rec(wth, wth->random_fh, rec, buf, err,
	    err_info)) {
		/* Read error or EOF */
		if (*err == 0) {
			/* EOF means "short read" in random-access mode */
			*err = WTAP_ERR_SHORT_READ;
		}
		return false;
	}
	return true;
}

static bool
radcom_read_rec(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
		int *err, char **err_info)
{
	struct radcomrec_hdr hdr;
	uint16_t data_length, real_length, length;
	uint32_t sec;
	struct tm tm;
	uint8_t	atmhdr[8];

	if (!wtap_read_bytes_or_eof(fh, &hdr, sizeof hdr, err, err_info))
		return false;

	data_length = pletoh16(&hdr.data_length);
	if (data_length == 0) {
		/*
		 * The last record appears to have 0 in its "data_length"
		 * field, but non-zero values in other fields, so we
		 * check for that and treat it as an EOF indication.
		 */
		*err = 0;
		return false;
	}
	length = pletoh16(&hdr.length);
	real_length = pletoh16(&hdr.real_length);
	/*
	 * The maximum value of length is 65535, which is less than
	 * WTAP_MAX_PACKET_SIZE_STANDARD will ever be, so we don't need to check
	 * it.
	 */

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

	tm.tm_year = pletoh16(&hdr.date.year)-1900;
	tm.tm_mon = (hdr.date.month&0x0f)-1;
	tm.tm_mday = hdr.date.day;
	sec = pletoh32(&hdr.date.sec);
	tm.tm_hour = sec/3600;
	tm.tm_min = (sec%3600)/60;
	tm.tm_sec = sec%60;
	tm.tm_isdst = -1;
	rec->ts.secs = mktime(&tm);
	rec->ts.nsecs = pletoh32(&hdr.date.usec) * 1000;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ETHERNET:
		/* XXX - is there an FCS? */
		rec->rec_header.packet_header.pseudo_header.eth.fcs_len = -1;
		break;

	case WTAP_ENCAP_LAPB:
		rec->rec_header.packet_header.pseudo_header.dte_dce.flags = (hdr.dce & 0x1) ?
		    0x00 : FROM_DCE;
		length -= 2; /* FCS */
		real_length -= 2;
		break;

	case WTAP_ENCAP_ATM_RFC1483:
		/*
		 * XXX - is this stuff a pseudo-header?
		 * The direction appears to be in the "hdr.dce" field.
		 */
		if (!wtap_read_bytes(fh, atmhdr, sizeof atmhdr, err,
		    err_info))
			return false;	/* Read error */
		length -= 8;
		real_length -= 8;
		break;
	}

	rec->rec_header.packet_header.len = real_length;
	rec->rec_header.packet_header.caplen = length;

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(fh, buf, length, err, err_info))
		return false;	/* Read error */

	return true;
}

static const struct supported_block_type radcom_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info radcom_info = {
	"RADCOM WAN/LAN analyzer", "radcom", NULL, NULL,
	false, BLOCKS_SUPPORTED(radcom_blocks_supported),
	NULL, NULL, NULL
};

void register_radcom(void)
{
	radcom_file_type_subtype = wtap_register_file_type_subtype(&radcom_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("RADCOM",
	    radcom_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
