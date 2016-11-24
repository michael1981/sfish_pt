#
# (C) Tenable Network Security, Inc.
#

# Ref :
# Date: Tue, 6 May 2003 19:14:40 -0700 (PDT)
# From: Dave Palumbo <dpalumbo@yahoo.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: [VulnDiscuss] XSS In Neoteris IVE Allows Session Hijacking
#
# This script was written by Renaud Deraison
# Special thanks to Dave for his help.

include( 'compat.inc' );

if(description)
{
  script_id(11608);
  script_version ("$Revision: 1.18 $");
  script_cve_id("CVE-2003-0217");
  script_bugtraq_id(7510);
  script_xref(name:"OSVDB", value:"7732");

  script_name(english:"Neoteris IVE swsrv.cgi XSS");
  script_summary(english:"Checks for a XSS is Neoteris IVE");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to cross site scripting.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running the Neoteris IVE.

There is a cross site scripting issue in this
server (in the CGI swsrv.cgi) which may allow
an attacker to perform a session hijacking."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to version 3.1 of Neoteris IVE."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=105283833617480&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (list_uniq(make_list( "/dana/fb/smb", cgi_dirs())))
{
 r = http_send_recv3(method: "GET", item:string(d, "/swsrv.cgi?wg=<script>foo</script>"), port:port);
 if (isnull(r)) exit(0);
 if( r[0] =~ "^HTTP/1\.[01] +200 " && egrep(pattern:"<script>foo</script>", string: r[2]) ){
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
