#include <include/lib.h>
/* Init the capture file struct */
void cap_file_init(capture_file *cf)
{
	/* Initialize the capture file struct */
	memset(cf, 0, sizeof(capture_file));
}
static const nstime_t * tshark_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
	if (prov->ref && prov->ref->num == frame_num)
			    return &prov->ref->abs_ts;
	if (prov->prev_dis && prov->prev_dis->num == frame_num)
			    return &prov->prev_dis->abs_ts;
	if (prov->prev_cap && prov->prev_cap->num == frame_num)
			    return &prov->prev_cap->abs_ts;
	if (prov->frames)
	{
		frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);
		return (fd) ? &fd->abs_ts : NULL;
	}
	return NULL;
}
/* Clean the capture file struct */
void clean()
{
	if (cfile.provider.frames != NULL)
	{
		/*
         * Free a frame_data_sequence and all the frame_data structures in it.
         */
		free_frame_data_sequence(cfile.provider.frames);
		cfile.provider.frames = NULL;
	}
	if (cfile.provider.wth != NULL)
	{
		/** Closes any open file handles and frees the memory associated with wth. */
		wtap_close(cfile.provider.wth);
		cfile.provider.wth = NULL;
	}
	if (cfile.epan != NULL)
	{
		epan_free(cfile.epan);
	}
	/** cleanup the whole epan module, this is used to be called only once in a program */
	epan_cleanup();
}
/* Fill data to the capture file struct */
int init(char *filename)
{
	int      err = 0;
	gchar   *err_info = NULL;
	e_prefs *prefs_p;
	/**
     * Called when the program starts, to enable security features and save
     * whatever credential information we'll need later.
     */
	init_process_policies();
	/**
     * Permanently relinquish special privileges. get_credential_info()
     * MUST be called before calling this.
     */
	relinquish_special_privs_perm();
	/**
     * @brief Initialize the Wiretap library.
     *
     * @param load_wiretap_plugins Load Wiretap plugins when initializing library.
    */
	wtap_init(TRUE);
	/**
     * Init the whole epan module.
     *
     * Must be called only once in a program.
     *
     * Returns TRUE on success, FALSE on failure.
     */
	epan_init(NULL, NULL, 0);
	cap_file_init(&cfile);
	cfile.filename = filename;
	cfile.provider.wth = wtap_open_offline(cfile.filename, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
	if (err != 0 || cfile.provider.wth == NULL)
	{
		clean();
		return err;
	}
	cfile.count = 0;
	cfile.provider.frames = new_frame_data_sequence();
	static const struct packet_provider_funcs funcs = {
					tshark_get_frame_ts,
										        NULL,
										        NULL,
										        NULL,
				}
				;
	cfile.epan = epan_new(&cfile.provider, &funcs);
	prefs_p = epan_load_settings();
	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);
	return 0;
}
/* Read each frame */
gboolean read_packet(epan_dissect_t **edt_r)
{
	epan_dissect_t    *edt;
	int                err;
	gchar             *err_info = NULL;
	static guint32     cum_bytes = 0;
	static gint64      data_offset = 0;
	wtap_rec rec;
	wtap_rec_init(&rec);
	/** Read the next record in the file, filling in *phdr and *buf.
     *
     * @wth a wtap * returned by a call that opened a file for reading.
     * @rec a pointer to a wtap_rec, filled in with information about the
     * record.
     * @buf a pointer to a Buffer, filled in with data from the record.
     * @param err a positive "errno" value, or a negative number indicating
     * the type of error, if the read failed.
     * @param err_info for some errors, a string giving more details of
     * the error
     * @param offset a pointer to a gint64, set to the offset in the file
     * that should be used on calls to wtap_seek_read() to reread that record,
     * if the read succeeded.
     * @return TRUE on success, FALSE on failure.
     */
	if (wtap_read(cfile.provider.wth, &rec, &cfile.buf, &err, &err_info, &data_offset))
	{
		cfile.count++;
		frame_data fdlocal;
		frame_data_init(&fdlocal, cfile.count, &rec, data_offset, cum_bytes);
		// data_offset must be correctly set
		data_offset = fdlocal.pkt_len;
		edt = epan_dissect_new(cfile.epan, TRUE, TRUE);
		prime_epan_dissect_with_postdissector_wanted_hfids(edt);
		/**
         * Sets the frame data struct values before dissection.
         */
		frame_data_set_before_dissect(&fdlocal, &cfile.elapsed_time, &cfile.provider.ref, cfile.provider.prev_dis);
		cfile.provider.ref = &fdlocal;
		tvbuff_t *tvb;
		tvb = tvb_new_real_data(cfile.buf.data, data_offset, data_offset);
		// core dissect process
		epan_dissect_run_with_taps(edt, cfile.cd_t, &rec, tvb, &fdlocal, &cfile.cinfo);
		frame_data_set_after_dissect(&fdlocal, &cum_bytes);
		cfile.provider.prev_cap = cfile.provider.prev_dis = frame_data_sequence_add(cfile.provider.frames, &fdlocal);
		// free space
		frame_data_destroy(&fdlocal);
		*edt_r = edt;
		return TRUE;
	}
	return FALSE;
}
/* Dissect and print all frames */
void print_all_frame()
{
	epan_dissect_t *edt;
	print_stream_t *print_stream;
	print_stream = print_stream_text_stdio_new(stdout);
	// start reading packets
	while (read_packet(&edt))
	{
		proto_tree_print(print_dissections_expanded, FALSE, edt, NULL, print_stream);
		epan_dissect_free(edt);
		edt = NULL;
	}
	clean();
}
/* Dissect and print the first frame */
void print_first_frame()
{
	epan_dissect_t *edt;
	print_stream_t *print_stream;
	print_stream = print_stream_text_stdio_new(stdout);
	// start reading packets
	if (read_packet(&edt))
	{
		proto_tree_print(print_dissections_expanded, FALSE, edt, NULL, print_stream);
		// print hex data
		print_hex_data(print_stream, edt);
		epan_dissect_free(edt);
		edt = NULL;
	}
	clean();
}
/* Dissect and print the first several frames */
void print_first_several_frame(int count)
{
	epan_dissect_t *edt;
	print_stream_t *print_stream;
	print_stream = print_stream_text_stdio_new(stdout);
	// start reading packets
	while (cfile.count < count)
	{
		read_packet(&edt);
		proto_tree_print(print_dissections_expanded, FALSE, edt, NULL, print_stream);
		// print hex data
		print_hex_data(print_stream, edt);
		epan_dissect_free(edt);
		edt = NULL;
	}
	clean();
}