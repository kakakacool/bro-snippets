##! Add fields to files.log that indicate the country and ASN
##! of the source and destination networks.
# Copyright (c) 2014, Broala LLC.

redef record Files::Info += {
	tx_cc: string &log &optional;
	rx_cc: string &log &optional;

	tx_asn: count &log &optional;
	rx_asn: count &log &optional;
};

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( ! f?$info )
		return;
	
	local orig_loc = lookup_location(c$id$orig_h);
	local resp_loc = lookup_location(c$id$resp_h);

	local orig_cc = orig_loc?$country_code ? orig_loc$country_code : "";
	local resp_cc = resp_loc?$country_code ? resp_loc$country_code : "";

	f$info$tx_cc = is_orig ? orig_cc : resp_cc;
	f$info$rx_cc = is_orig ? resp_cc : orig_cc;

	f$info$tx_asn = is_orig ? lookup_asn(c$id$orig_h) : lookup_asn(c$id$resp_h);
	f$info$rx_asn = is_orig ? lookup_asn(c$id$resp_h) : lookup_asn(c$id$orig_h);
	}