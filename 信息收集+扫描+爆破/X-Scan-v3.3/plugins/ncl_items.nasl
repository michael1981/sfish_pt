#
# (C) Tenable Network Security, Inc.
#

# Reference:
# http://members.cox.net/ltlw0lf/printers.html
#

include( 'compat.inc' );

if(description)
{
 script_id(10146);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1508");
 script_bugtraq_id(806);
 script_xref(name:"OSVDB", value:"113");

 script_name(english:"Tektronix PhaserLink Printer Web Server Direct Request Administrator Access");
 script_summary(english:"Checks for the presence of /ncl_*.html");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to unauthorized access.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The file /ncl_items.html or /ncl_subjects.html exist on the remote system.
It is very likely that this file will allow an attacker
to reconfigure your Tektronix printer.

An attacker can use this to prevent the users of your
network from working properly by preventing them
from printing their files."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Filter incoming traffic to port 80 to this device, or disable
the Phaserlink webserver on the printer (can be done by requesting
http://printername/ncl_items?SUBJECT=2097)"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2001-04/0482.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P'
  );

  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

i = "/ncl_items.html?SUBJECT=1";
if (is_cgi_installed_ka(item: i, port: port))
{
  if (!is_cgi_installed_ka(item: "/nessus" + rand() + ".html", port: port) )
  {
    security_warning(port);
    exit(0);
  }
}

if (is_cgi_installed_ka(item: "/ncl_subjects.html", port: port) )
{
    if (!is_cgi_installed_ka(item: "/nessus" + rand() + ".html", port: port) ) security_warning(port);
}
