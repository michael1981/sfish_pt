#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(11597);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2003-0492", "CVE-2003-0494");
  script_bugtraq_id(7381, 7922, 7925);
  script_xref(name:"OSVDB", value:"3297");
  script_xref(name:"OSVDB", value:"4320");

  script_name(english:"Snitz Forums 2000 3.4.03 Multiple Vulnerabilities");
  script_summary(english:"Determine if Snitz forums is vulnerable to xss attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to injection attacks.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is using Snitz Forum 2000.

This set of CGI is vulnerable to a cross-site-scripting issue
that may allow attackers to steal the cookies of your
users.

In addition to this flaw, a user may use the file Password.ASP to
reset arbitrary passwords, therefore gaining administrative access
on this web system.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'The vendor has released a patch. http://forum.snitz.com/'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2003-06/0110.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = list_uniq("/forum", cgi_dirs());

foreach d (dir)
{
 url = string(d, '/search.asp');
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);

 # Ex: Powered By: Snitz Forums 2000 Version 3.4.03
 if ("Powered By: Snitz Forums 2000" >< r[2])
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
