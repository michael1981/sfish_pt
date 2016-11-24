#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(21243);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-0992");
  script_bugtraq_id (17503);
  script_xref(name:"OSVDB", value:"24617");

  script_name(english:"Novell GroupWise Messenger Accept Language Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell Messenger Messaging Agent, an
enterprise instant messaging server for Windows, Linux, and NetWare. 

This version of this service is running an HTTP server which is
vulnerable to a stack overflow. 

An attacker can exploit this vulnerability to execute code on the
remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Groupwise Messenger 2.0.1 beta3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_summary(english:"Checks for Novell Messenger Messaging Agent Buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencie("nmma_detection.nasl");
  script_require_ports("Services/www", 8300);

  exit(0);
}

include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:8300);
kb = get_kb_item("Novel/NMMA/" + port);
if (!kb) exit(0);

if (!get_port_state(port))
  exit (0);

# getlocation command was not in 2.0.0
data = string ("GET /getlocation HTTP/1.0\r\n\r\n");

buf = http_keepalive_send_recv (port:port, data:data);

# patched version replies with the download page

if (egrep (pattern:"^HTTP/1.0 200", string:buf) && ("NM_A_SZ_RESULT_CODE" >!< buf))
  security_hole(port);
