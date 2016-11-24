#
# (C) Tenable Network Security, Inc.
#

#
# This script was rewritten by Tenable Network Security, Inc., using a new HTTP API.
#
# Did not really check CVE-2002-1276, since it`s the same kind of problem.
#


include("compat.inc");

if (description)
{
 script_id(11415);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2002-1341");
 script_bugtraq_id(6302);
 script_xref(name:"RHSA", value:"RHSA-2003:0042-07");
 script_xref(name:"OSVDB", value:"4266");

 script_name(english:"SquirrelMail 1.2.9 / 1.2.10 read_body.php Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be vulnerable to a security problem in
SquirrelMail. The 'read_body.php' script doesn't filter out user
input for multiple parameters, allowing for XSS attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

test_cgi_xss(port: port, cgi: "/read_body.php", dirs: cgi_dirs(),
 qs: "mailbox=<script>alert(document.cookie)</script>&passed_id=<script>alert(document.cookie)</script>&startMessage=1&show_more=0",
 pass_str: "<script>alert(document.cookie)</script>" );
