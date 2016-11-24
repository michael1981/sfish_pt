#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15951);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2509", "CVE-2004-2510");
 script_bugtraq_id(11900);
 script_xref(name:"OSVDB", value:"12364");
 script_xref(name:"OSVDB", value:"12365");
 script_xref(name:"OSVDB", value:"12366");
 script_xref(name:"OSVDB", value:"12367");

 script_name(english:"UBB.threads < 6.5.1 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to 
various cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"There are various cross-site scripting issues in the remote version of
this software.  An attacker may exploit them to use the remote website
to inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0239.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to UBB.Threads version 6.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "XSS UBB.threads";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl", "ubbthreads_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 r = http_send_recv3(method:"GET", port:port, item: dir + "/calendar.php?Cat=<script>foo</script>");
 if (isnull(r)) exit(0);
 res = r[2];
 if ( "<script>foo</script>" >< res )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
