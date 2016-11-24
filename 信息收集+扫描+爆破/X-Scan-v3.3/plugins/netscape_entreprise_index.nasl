#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10691);
  script_version ("$Revision: 1.18 $");
  script_cve_id("CVE-2001-0250");
  script_bugtraq_id(2285);
  script_xref(name:"OSVDB", value:"571");

  script_name(english:"Netscape Enterprise Web Publishing INDEX Command Arbitrary Directory Listing");
  script_summary(english:"INDEX / HTTP/1.1 Information Disclosure");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server gives a file listing when it is issued the command :

    INDEX / HTTP/1.1

An attacker may use this flaw to discover the internal
structure of your website, or to discover supposedly hidden
files.
"
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable web publishing or INDEX requests."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2001-01/0396.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/iplanet");
  exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  req = string("INDEX / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  close(soc);
  if("Content-Type: text/plain" >< r)
  {
   if("null" >< r)
  {
   if(egrep(pattern:"directory|unknown", string:r))security_warning(port);
  }
 }
}
