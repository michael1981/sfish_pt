#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10349);
  script_version ("$Revision: 1.25 $");
  script_cve_id("CVE-2000-0180");
  script_bugtraq_id(1052);
  script_xref(name:"OSVDB", value:"265");

  script_name(english:"Sojourn Search Engine sojourn.cgi cat Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/sojourn.cgi");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The \'sojourn.cgi\' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Remove the \'sojourn.cgi\' CGI.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/ntbugtraq/2000-q1/0201.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
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
 rq = string(dir, "/sojourn.cgi?cat=../../../../../etc/passwd%00");
 rq = http_get(item:rq, port:port);
 r = http_keepalive_send_recv(port:port, data:rq);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
 }
}
