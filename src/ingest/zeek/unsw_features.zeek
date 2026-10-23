##! Per-connection packet statistics that UNSW-NB15 used and conn.log does not
##! carry: TTLs, TCP windows, initial sequence numbers, inter-packet timing,
##! jitter, retransmissions, handshake timing and FTP command counts.
##!
##! UNSW-NB15 built its features with Argus (packet-level flow stats) and Bro
##! (application-level fields). Zeek is Bro's successor, so the application
##! features come from the standard logs. The Argus-side features are recomputed
##! here, one record per connection, written to unsw.log and joined to conn.log
##! on uid.
##!
##! Where Argus's exact definition is not documented (first vs last TTL, first vs
##! last window, which jitter formula), this script logs every candidate and the
##! Python adapter picks one by measured agreement on a calibration capture.
##!
##! Cost: this handles new_packet, which runs script code for every packet. Fine
##! for batch pcap scoring. For a live sensor it would move to a plugin.

@load base/protocols/conn
@load base/protocols/ftp

module UNSWFeatures;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                time   &log;
		uid:               string &log;
		## Orig/resp TTL of the first and last packet in each direction.
		s_ttl_first:       count  &log &optional;
		s_ttl_last:        count  &log &optional;
		d_ttl_first:       count  &log &optional;
		d_ttl_last:        count  &log &optional;
		## TCP window: first, last and max advertised value per direction.
		s_win_first:       count  &log &optional;
		s_win_last:        count  &log &optional;
		s_win_max:         count  &log &optional;
		d_win_first:       count  &log &optional;
		d_win_last:        count  &log &optional;
		d_win_max:         count  &log &optional;
		## TCP initial sequence number per direction (first packet seen).
		s_isn:             count  &log &optional;
		d_isn:             count  &log &optional;
		## Inter-packet arrival, milliseconds: mean and standard deviation, and
		## the mean absolute difference between consecutive gaps (RFC 3550 style).
		s_ipt_mean_ms:     double &log &optional;
		s_ipt_std_ms:      double &log &optional;
		s_ipt_mad_ms:      double &log &optional;
		d_ipt_mean_ms:     double &log &optional;
		d_ipt_std_ms:      double &log &optional;
		d_ipt_mad_ms:      double &log &optional;
		## Data packets whose bytes were already seen in that direction.
		s_retrans:         count  &log &default=0;
		d_retrans:         count  &log &default=0;
		## Handshake timing, seconds. synack: SYN -> SYN/ACK.
		## ackdat: SYN/ACK -> first ACK from the originator.
		synack:            double &log &optional;
		ackdat:            double &log &optional;
		## FTP commands seen on this connection, and whether USER and PASS both
		## appeared with a non-empty user.
		ftp_cmds:          count  &log &default=0;
		ftp_login:         bool   &log &default=F;
	};
}

type DirState: record {
	pkts:        count  &default=0;
	ttl_first:   count  &optional;
	ttl_last:    count  &optional;
	win_first:   count  &optional;
	win_last:    count  &optional;
	win_max:     count  &default=0;
	isn:         count  &optional;
	last_ts:     time   &optional;
	prev_gap:    double &optional;
	gap_n:       count  &default=0;
	gap_sum:     double &default=0.0;
	gap_sq:      double &default=0.0;
	jit_n:       count  &default=0;
	jit_sum:     double &default=0.0;
	seq_hi:      count  &default=0;
	seq_seen:    bool   &default=F;
	retrans:     count  &default=0;
};

type ConnState: record {
	o:          DirState;
	r:          DirState;
	syn_ts:     time &optional;
	synack_ts:  time &optional;
	ack_ts:     time &optional;
	ftp_cmds:   count &default=0;
	ftp_user:   bool  &default=F;
	ftp_pass:   bool  &default=F;
};

global states: table[string] of ConnState;

const TH_SYN = 2;
const TH_ACK = 16;

event zeek_init()
	{
	Log::create_stream(UNSWFeatures::LOG, [$columns=Info, $path="unsw"]);
	}

function get_state(c: connection): ConnState
	{
	if ( c$uid !in states )
		states[c$uid] = ConnState($o=DirState(), $r=DirState());
	return states[c$uid];
	}

function packet_is_orig(c: connection, p: pkt_hdr): bool
	{
	if ( p$ip$src != p$ip$dst )
		return p$ip$src == c$id$orig_h;
	# Same address both ways (land-style traffic): fall back to ports.
	if ( p?$tcp )
		return p$tcp$sport == c$id$orig_p;
	if ( p?$udp )
		return p$udp$sport == c$id$orig_p;
	return T;
	}

function update_dir(d: DirState, p: pkt_hdr)
	{
	local now = network_time();
	d$pkts += 1;
	if ( ! d?$ttl_first )
		d$ttl_first = p$ip$ttl;
	d$ttl_last = p$ip$ttl;

	if ( d?$last_ts )
		{
		local gap = interval_to_double(now - d$last_ts) * 1000.0;
		d$gap_n += 1;
		d$gap_sum += gap;
		d$gap_sq += gap * gap;
		if ( d?$prev_gap )
			{
			d$jit_n += 1;
			d$jit_sum += |gap - d$prev_gap|;
			}
		d$prev_gap = gap;
		}
	d$last_ts = now;

	if ( ! p?$tcp )
		return;

	if ( ! d?$win_first )
		d$win_first = p$tcp$win;
	d$win_last = p$tcp$win;
	if ( p$tcp$win > d$win_max )
		d$win_max = p$tcp$win;
	if ( ! d?$isn )
		d$isn = p$tcp$seq;

	# Retransmission: a data segment ending at or before the highest byte
	# already seen in this direction. Sequence wraparound is ignored, which
	# only matters for flows that move ~4 GB.
	if ( p$tcp$dl > 0 )
		{
		local seq_end = p$tcp$seq + p$tcp$dl;
		if ( d$seq_seen && seq_end <= d$seq_hi )
			d$retrans += 1;
		else
			{
			d$seq_hi = seq_end;
			d$seq_seen = T;
			}
		}
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( ! p?$ip )
		return;   # UNSW-NB15 is IPv4 only

	local st = get_state(c);
	local is_orig = packet_is_orig(c, p);
	update_dir(is_orig ? st$o : st$r, p);

	if ( ! p?$tcp )
		return;

	local flags = p$tcp$flags;
	local syn = (flags & TH_SYN) != 0;
	local ack = (flags & TH_ACK) != 0;
	local now = network_time();

	if ( is_orig && syn && ! ack && ! st?$syn_ts )
		st$syn_ts = now;
	else if ( ! is_orig && syn && ack && ! st?$synack_ts )
		st$synack_ts = now;
	else if ( is_orig && ack && ! syn && st?$synack_ts && ! st?$ack_ts )
		st$ack_ts = now;
	}

event ftp_request(c: connection, command: string, arg: string)
	{
	local st = get_state(c);
	st$ftp_cmds += 1;
	local cmd = to_upper(command);
	if ( cmd == "USER" && arg != "" )
		st$ftp_user = T;
	else if ( cmd == "PASS" )
		st$ftp_pass = T;
	}

event connection_state_remove(c: connection)
	{
	if ( c$uid !in states )
		return;
	local st = states[c$uid];
	delete states[c$uid];

	local rec = Info($ts=c$start_time, $uid=c$uid,
	                 $s_retrans=st$o$retrans, $d_retrans=st$r$retrans,
	                 $ftp_cmds=st$ftp_cmds,
	                 $ftp_login=(st$ftp_user && st$ftp_pass));

	local o = st$o;
	local r = st$r;

	if ( o?$ttl_first ) { rec$s_ttl_first = o$ttl_first; rec$s_ttl_last = o$ttl_last; }
	if ( r?$ttl_first ) { rec$d_ttl_first = r$ttl_first; rec$d_ttl_last = r$ttl_last; }
	if ( o?$win_first ) { rec$s_win_first = o$win_first; rec$s_win_last = o$win_last; rec$s_win_max = o$win_max; }
	if ( r?$win_first ) { rec$d_win_first = r$win_first; rec$d_win_last = r$win_last; rec$d_win_max = r$win_max; }
	if ( o?$isn ) rec$s_isn = o$isn;
	if ( r?$isn ) rec$d_isn = r$isn;

	if ( o$gap_n > 0 )
		{
		local om = o$gap_sum / o$gap_n;
		rec$s_ipt_mean_ms = om;
		local ov = o$gap_sq / o$gap_n - om * om;
		rec$s_ipt_std_ms = ov > 0.0 ? sqrt(ov) : 0.0;
		rec$s_ipt_mad_ms = o$jit_n > 0 ? o$jit_sum / o$jit_n : 0.0;
		}
	if ( r$gap_n > 0 )
		{
		local rm = r$gap_sum / r$gap_n;
		rec$d_ipt_mean_ms = rm;
		local rv = r$gap_sq / r$gap_n - rm * rm;
		rec$d_ipt_std_ms = rv > 0.0 ? sqrt(rv) : 0.0;
		rec$d_ipt_mad_ms = r$jit_n > 0 ? r$jit_sum / r$jit_n : 0.0;
		}

	if ( st?$syn_ts && st?$synack_ts )
		rec$synack = interval_to_double(st$synack_ts - st$syn_ts);
	if ( st?$synack_ts && st?$ack_ts )
		rec$ackdat = interval_to_double(st$ack_ts - st$synack_ts);

	Log::write(UNSWFeatures::LOG, rec);
	}
