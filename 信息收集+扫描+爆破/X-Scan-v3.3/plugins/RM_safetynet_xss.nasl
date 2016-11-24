#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: snkenjoi at gmail.com

# This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title (5/27/09)

include("compat.inc");

if(description)
{
  script_id(18182);
  script_version("$Revision: 1.6 $");
  script_xref(name:"OSVDB", value:"15543");
  
  script_name(english:"RM SafetyNet Plus snpfiltered.pl u Parameter XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web filtering application has a cross-site vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running SafetyNet Plus, an educational web
filtering application.

This version is vulnerable to a cross-site scripting attack.  Input
to the 'u' parameter of snpfiltered.pl is not properly sanitized.  A
remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this application."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_summary(english:"Checks RM SafetyNet Plus XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/snpfiltered.pl?t=c&u=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);

  if (ereg(pattern:"RM SafetyNet Plus</title>", string:r, icase:1) && ("<script>foo</script>" >< r))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
    check(req:dir);
}
