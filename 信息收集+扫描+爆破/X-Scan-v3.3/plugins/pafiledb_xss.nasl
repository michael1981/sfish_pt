#
# (C) Tenable Network Security, Inc.
#

# From: <ersatz@unixhideout.com>
# To: bugtraq@securityfocus.com
# Subject: XSS vulnerabilites in Pafiledb



include("compat.inc");

if (description)
{
 script_id(11479);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2002-1931", "CVE-2005-0952");
 script_bugtraq_id(6021);
 script_xref(name:"OSVDB", value:"15809");
 
 script_name(english:"paFileDB pafiledb.php id Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by cross-
site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The version of paFileDB installed on the remote host is vulnerable to
cross-site scripting attacks due to its failure to sanitize input to
the 'id' parameter of the 'pafiledb.php' script before using it to
generate dynamic HTML.  An attacker may use these flaws to steal
cookies of users of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-10/0305.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to paFileDB 3.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if pafiledb is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("pafiledb_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 test_cgi_xss(port: port, dirs: make_list(d), cgi: '/pafiledb.php',
 qs: 'action=download&id=4?"<script>alert(foo)</script>"',
 pass_str: "<script>alert(foo)</script>");
}
