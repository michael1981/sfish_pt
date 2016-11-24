#
# Copyright (C) Tenable Network Security 
#


include("compat.inc");

if(description)
{
 script_id(21271);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2006-0230","CVE-2006-0231","CVE-2006-0232");
 script_bugtraq_id(17637);
 script_xref(name:"OSVDB", value:"24902");
 script_xref(name:"OSVDB", value:"24903");
 script_xref(name:"OSVDB", value:"24904");

 script_name(english:"Symantec AntiVirus Scan Engine Web Interface Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to take control of the remote scan engine." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Symantec Scan Engine.

This version of Scan Engine is vulnerable to multiple flaws which may
allow a remote attacker to take control of the scan engine. Following
flaws are present:

- Fixed HTTPS certificate key
- Configuration file retrieval (with administrator password hash)
- Possibility to change the administrator password" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Scan Engine 5.1.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Checks if Symantec Scan Engine is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8004);
 exit(0);
}

include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

port = get_http_port(default:8004);

r = http_get_cache(item:"/", port:port);
if ( (!r) || ("<title>Scan Engine</title>" >!< r) || ("com.symantec.gui" >!< r) )
  exit(0);


req = string("GET /configuration.xml\\ HTTP/1.0\r\n\r\n");

buf = http_send_recv_buf(port:port, data:req);
if (!buf) exit (0);


if (("<password value=" >< buf) && ("AutomaticSendVirusUpdatesEnabled" >< buf))
{
 line = egrep(pattern:".*password value=", string:buf);
 pass = ereg_replace (pattern:'.*<password value="([A-Z0-9]+)"/>.*', string:line, replace:"\1");
 report = string ("The administrator password hash (from the configuration file) is:\n\n",		
		pass);

 security_hole(port: port, extra:report);
 exit(0);
}
