#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14836);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2004-1559");
 script_bugtraq_id(11268);
 script_xref(name:"OSVDB", value:"10410");
 script_xref(name:"OSVDB", value:"10411");
 script_xref(name:"OSVDB", value:"10412");
 script_xref(name:"OSVDB", value:"10413");
 script_xref(name:"OSVDB", value:"10414");
 script_xref(name:"OSVDB", value:"10415");

 script_name(english:"WordPress < 1.2.2 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote version of WordPress is vulnerable to cross-site scripting
issues due to a failure of the application to properly sanitize user-
supplied URI input. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 
This may facilitate the theft of cookie-based authentication
credentials as well as other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/376766" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.2.2 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for the presence of WordPress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("wordpress_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 test_cgi_xss(port: port, dirs: make_list(loc), cgi: "/wp-login.php", qs: "redirect_to=<script>foo</script>",
  pass_str: "<script>foo</script>", 
  ctrl_re:  '<form name="login" id="loginform" action="wp-login.php" method="post">' );
}
