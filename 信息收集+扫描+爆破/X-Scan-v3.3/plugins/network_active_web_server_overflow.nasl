#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15421);
  script_version("$Revision: 1.4 $");
  script_bugtraq_id(11326);
  script_xref(name:"OSVDB", value:"10489");

  script_name(english:"NetworkActiv Web Server Encoded URL Request Remote DoS");
  script_summary(english:"Checks for version of NetworkActive Web Server");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running NetworkActive Web Server - an alternative web server.

There is a vulnerability in the remote version of this software which may allow
an attacker to cause a denial of service against the remote server by sending
an HTTP GET request containing a '%25' character."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to NetworkActive Web Server version 2.0 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.networkactiv.com/WebServer.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if ( egrep(pattern:"^Server: NetworkActiv-Web-Server/(0\.[0-9]|1\.0[^0-9])", string:banner) )
 {
   security_warning(port);
 }
