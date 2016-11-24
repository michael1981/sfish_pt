#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10503);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-2000-0868");
  script_bugtraq_id(1658);
  script_xref(name:"OSVDB", value:"402");

  script_name(english:"Apache on SuSE Linux cgi-bin-sdb Request Script Source Disclosure");
  script_summary(english:"Checks for the presence of /cgi-bin-sdb/");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The directory /cgi-bin-sdb is an Alias of
/cgi-bin - most SuSE systems are configured that
way.

This setting allows an attacker to obtain the source
code of the installed CGI scripts on this host. This is
dangerous as it gives an attacker valuable information
about the setup of this host, or perhaps usernames and
passwords if they are hardcoded into the CGI scripts.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'In httpd.conf, change the directive:
Alias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/
to
ScriptAlias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/linux/suse/2000-q3/0906.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
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


if(get_port_state(port))
{
  # First try : attempt to get printenv
  req = string("/cgi-bin-sdb/printenv");
  req = http_get(item:req, port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  if("/usr/bin/perl" >< r)
  {
  	security_warning(port);
	exit(0);
  }
}
