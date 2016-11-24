#
# (C) Tenable Network Security, Inc.
#

# Revised 19/02/05 by Martin O'Neal of Corsaire to make the detection more positive, include the 
#                  correct CVE and to update the knowledgebase appropriately 
#


include("compat.inc");

if(description)
{
 script_id(11819);
 script_version ("$Revision: 1.18 $");
 
 script_name(english:"TFTP Daemon Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"A TFTP server is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a TFTP (Trivial File Transfer Protocol)
daemon.  TFTP is often used by routers and diskless hosts to retrieve
their configuration.  It is also used by worms to propagate." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
 summary["english"] = "Tries to retrieve a nonexistent file";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Service detection";
 script_family(english:family["english"]);
 script_dependencies('external_svc_ident.nasl');
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include('misc_func.inc');
if ( TARGET_IS_IPV6 ) exit(0);

if(islocalhost())exit(0);

file = string("nessus" + rand());
foreach mode (make_list("netascii", "octet"))
{
  req = raw_string(0x00, 0x01) + file + raw_string(0x00) + mode + raw_string(0x00);
  sport = rand() % 64512 + 1024;		     

  ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, ip_len:20, ip_id:rand(), ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
		     ip_src:this_host());
  myudp = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:69, uh_ulen: 8 + strlen(req), data:req);

  # Some backdoors never return "file not found"
  # filter = 'udp and dst port 4315 and src host ' + get_host_ip() + ' and udp[9:1]=0x05';
  filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

  rep = NULL;
  for ( i = 0 ; i < 3 ; i ++ )
  {
   rep = send_packet(myudp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);	     
   if ( rep ) break;
  }
  if ( rep ) break;
}

if(rep)
{
 data = get_udp_element(udp:rep, element:"data");
 if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05'))
 {
  security_note(port:69, proto:"udp");
  register_service(port: 69, ipproto: 'udp', proto: 'tftp');
 }
}
