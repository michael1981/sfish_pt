#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: office <office@office.ac>
#
#  This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/1/09)

include("compat.inc");

if(description)
{
 script_id(14823);
 script_version ("$Revision: 1.12 $"); 
 script_cve_id("CVE-2002-0771");
 script_bugtraq_id(4818);
 script_xref(name:"OSVDB", value:"6458");

 script_name(english:"ViewCVS viewcvs.cgi Multiple Parameter XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running ViewCVS, a tool written in Python to
browse CVS repositories via the web.

The version of ViewCVS running on the remote host has a cross-site
scripting vulnerability.  Input to the 'viewcvs' parameter is not
properly sanitized.  A remote attacker could exploit this by tricking
a user into requesting a maliciously crafted URL, resulting in the
execution of arbitrary script code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2002-05/0161.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

 summary["english"] = "Checks for the version of ViewCVS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(url)
{
  local_var r, req;
  req = http_get(item:string(url, "/viewcvs.cgi/?cvsroot=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);

  if ('The CVS root "<script>foo</script>" is unknown' >< r)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}


foreach dir (cgi_dirs())
{
 check(url:dir);
}
