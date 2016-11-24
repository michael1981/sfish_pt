#
# (C) Tenable Network Security, Inc.
#

#
# Problem: This check is prone to false negatives (if the remote FW
#          does not allow outgoing icmp-unreach packets [default on kerio]).
#	   However I've decided to include this plugin anyway as it might
#	   uncover issues in other firewalls.
# 

include("compat.inc");

if (description)
{
  script_id(11580);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2003-1491", "CVE-2004-1473");
  script_bugtraq_id(7436, 11237);
  script_xref(name:"OSVDB", value:"10205");
  script_xref(name:"OSVDB", value:"60212");
 
  script_name(english:"Firewall UDP Packet Source Port 53 Ruleset Bypass");
  script_summary(english:"By-passes the remote firewall rules");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"Firewall rulesets can be bypassed."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It is possible to bypass the rules of the remote firewall by sending
UDP packets with a source port equal to 53. 

An attacker may use this flaw to inject UDP packets to the remote
hosts, in spite of the presence of a firewall."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q2/0352.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://securityresponse.symantec.com/avcenter/security/Content/2004.09.22.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Either contact the vendor for an update or review the firewall rules
settings."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2003/04/23"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2004/09/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2003/05/06"
  );
  script_end_attributes();
 
  script_category(ACT_ATTACK); 
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  exit(0);
}

include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

if ( islocalhost() ) exit(0);

function check(sport)
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
        uh_dport:1026,
        uh_ulen :8
        );
	
  filter = string("src host ", get_host_ip(), " and dst host ", this_host(),
 " and icmp and (icmp[0] == 3  and icmp[28:2]==", sport, ")");
  for(i=0;i<3;i++)
  	{
  	res = send_packet(udppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
	if(!isnull(res))return(1);
	}
 return(0);
}

if(check(sport:1025) == 1)
{
 exit(0);
}

if(check(sport:53) == 1)
{
 security_hole(proto:"udp", port:0);
}
