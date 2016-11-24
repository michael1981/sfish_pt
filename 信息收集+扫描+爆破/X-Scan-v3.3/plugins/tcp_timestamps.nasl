#TRUSTED 7d3607b3c4d5810a531e12e339e22a8df56ffe8a3d596d176f68909a9caf54a158999ec950c0e3cd8a40dfded1d87d28606767f3cfbbacd2d549442161c92144eb5a12747e5986051bf76fc2134bd5febd8ac35579e5f68f27d65837eff17467767fc360970cbcaa0d15c336e14b75eca0de73a56d22bf7a357881bbfa5a8e786fc38f8649d12de15b8392d87285eb760f4283b2237564d876cb08c31c54a5f04e0f6e5c5f647a8b13863f48d8b973e43360560edc7ed6b69eb17e95f8667fb272ef06db8d3ecda6e6f80910e2a05ff073ade0658abe9b7b3431a332cba15e00cc0706b7885cac75989effa35c44d05984cff8af7c3e276a3249da25328a2c385572a0b0d1225b7b94d73fb5eaad583af44692b3b6b9a97dacb635e6d43f4115ff84629ff05fde78f44cad680d45115428082f374f84049c3bf7fbc81cce9d824274d5ecefd41e3fa133379221ad64eecd2c383998e288800619d6a9d1789a28412f76909c583573d8c7dad64894e082f2afce3ce8b47c73e6350e68a8ef30998a0e4f33844f8d1f6d09599439cb13d2c333c45dbbee165e56520e13197930f50f8021bdba16e8ad296d387fd9bd6437a1710c656b5129b4be713b2552532ac164031614b65d1f72137d04b2632a2d2b08e82f5a453c93290a12e7807a65e196fa931ca39fac791e0dad3dfd4d335bebe98bf40f81c1ec4c54138577c1e29af9
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25220);
  script_version("1.15");

  script_name(english: "TCP/IP Timestamps Supported");
  script_summary(english: "Look at RFC1323 TCP timestamps"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote service implements TCP timestamps." );
 script_set_attribute(attribute:"description", value:
"The remote host implements TCP timestamps, as defined by RFC1323.  A
side effect of this feature is that the uptime of the remote host can
sometimes be computed." );
 script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc1323.txt" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "General");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  exit(0);
}


include("raw.inc");

function ms_since_midnight()
{
  local_var     v, s, u;

  if (defined_func("gettimeofday"))
  {
    v = split(gettimeofday(), sep: '.', keep: 0);
    s = int(v[0]); u = int(v[1]);
    s %= 86400;
    u /= 1000;
    return u + 1000 * s;
  }

  if (defined_func("unixtime"))
  {
    s = unixtime();
    s %= 86400;
    return s * 1000;
  }

  return NULL;
}




if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(0);

dport = get_host_open_port(); 
if (! dport) exit(0);

daddr = get_host_ip();
saddr = this_host();


function test(seq)
{
 local_var ip, tcp, options, filter, ms, r, sport, tsval;
 local_var i;
 local_var pkt;

 sport = rand() % (65536 - 1024) + 1024;
 ip = ip(ip_p:IPPROTO_TCP);
 tcp = tcp(th_sport:sport, th_dport:dport, th_flags:TH_SYN, th_win:512);
 tcp = tcp_insert_option(tcp:tcp, type:0x08, length:0x0A, data:mkdword(seq) + mkdword(0) + '\0x01\0x01');
 tcp = tcp_finish_insert_option(tcp:tcp);

 filter = strcat('tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport);
 if ( ! defined_func("link_layer") )  RawSendViaOperatingSystem = 1;
 pkt = mkpacket(ip, tcp);
 for ( i = 0 ; i < 5 ; i ++ )
 {
  if ( ! defined_func("link_layer") )
  {
    r = send_packet(pkt,  pcap_active: TRUE, pcap_filter: filter, pcap_timeout:1);
    if ( !isnull(r) ) break;
  }
  else 
  {
   r = inject_packet(packet:link_layer() + pkt,filter:filter, timeout:1);
   if ( !isnull(r) ) 
	{
	 r = substr(r, strlen(link_layer()), strlen(r) - 1);
	 break; 
	}
   }
  }
 if ( r == NULL ) return NULL;
 ms = ms_since_midnight();

 pkt = packet_split(r);
 if ( isnull(pkt) ) return NULL;
 pkt = pkt[1];
 if ( isnull(pkt) || pkt["type"] != "tcp" ) return NULL;
 pkt = pkt["data"];
 if ( ! ( pkt["th_flags"] & TH_ACK) ) return NULL;
 if ( isnull(pkt["options"]) ) return NULL;
 tsval = tcp_extract_timestamp(pkt["options"]);
 if (isnull(tsval)) return NULL;
 return make_list(ms, tsval);
}

function tcp_extract_timestamp()
{
 local_var opt, lo, n, i, tsval, tsecr, len;
 
 opt = _FCT_ANON_ARGS[0];
 lo = strlen(opt);
 for (i = 0; i < lo; )
 {
  n = ord(opt[i]);
  if (n == 8)	# Timestamp
  {
   tsval = getdword(blob: substr(opt, i+2, i+5), pos:0);
   tsecr = getdword(blob: substr(opt, i+6, i+9), pos:0);
   #debug_print(level: 2, "TSVal=", tsval, " TSecr=", tsecr, "\n");
   return tsval;
  }
  else if (n == 1)	# NOP
   i ++;
  else
  {
   if ( i + 1 < strlen(opt) )
    len = ord(opt[i+1]);
   else 
    len = 0;
   if ( len == 0 ) break;
   i += len;
  }
 }
 return NULL;
}

function sec2ascii(txt, s)
{
 if (s < 60) return '';
 if (s < 3600)
  return strcat(txt, (s + 29) / 60, ' min');
 else if (s < 86400)
  return strcat(txt, (s + 1799) / 3600, ' hours');
 else
  return strcat(txt, (s + 23199) / 86400, ' days');
}

####

v1 = test(seq:1);

if (isnull(v1)) exit(0);

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
sleep(1);	# Bigger sleep values make the test more precise

v2 = test(seq: 2);
if (isnull(v2)) exit(1); # ???
else
{
 dms = v2[0] - v1[0];
 dseq = v2[1] - v1[1];

 #
 # Disable the uptime computation (unreliable)
 #
 if ( TRUE || dseq == 0 || v2[1] < 0)
 {
  security_note();
 }
 else
 {
  hz = dseq * 1000 / dms; hz0 = hz;
  # Round clock speed
  if (hz > 500) { hz = (hz + 25) / 50; hz *= 50; }
  else if (hz > 200) { hz = (hz + 5) / 10; hz *= 10; }
  else if (hz > 50) { hz = (hz + 2) / 5; hz *= 5; }
  #debug_print('dms = ', dms, ' - dseq = ', dseq, ' - clockspeed = ', hz0, ' rounded = ', hz, '\n');
  uptime = v2[1] / hz;
  #uptime = v2[1] * (dms / dseq) / 1000;
  txt = '';
  txt = sec2ascii(txt: ', i.e. about ', s: uptime);
  ov = (1 << 30) / hz; ov <<= 2;
  txt = strcat(txt, '.\n\n(Note that the clock is running at about ', 
	hz, ' Hz', 
	' and will\noverflow in about ', ov, 's', 
	sec2ascii(txt: ', that is ', s: ov));
  security_note(port: 0, 
	extra:strcat('The uptime was estimated to ', 
		uptime, 's', 
		txt, ')') );
 }
}
