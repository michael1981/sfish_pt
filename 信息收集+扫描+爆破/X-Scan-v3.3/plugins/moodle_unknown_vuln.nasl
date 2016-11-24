#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(13843);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2004-0725");
 script_bugtraq_id(10718);
 script_xref(name:"OSVDB", value:"7865");
 script_xref(name:"Secunia", value:"12065");

 script_name(english:"Moodle < 1.3.3 Cross-Site Scripting Vulnerability");
 script_summary(english:"Attempts a non-persistent XSS");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server contains a PHP application that is affected\n",
     "by a cross-site scripting vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of Moodle running on the remote host has a cross-site\n",
     "scripting vulnerability.  Input to the 'file' parameter of help.php\n",
     "is not properly sanitized.  A remote attacker could exploit this by\n",
     "tricking a user into requesting a maliciously crafted URL, resulting\n",
     "in stolen credentials."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-07/0116.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Moodle 1.3.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("moodle_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 url = string(dir, "/help.php?file=<script>foo</script>");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The web server didn't respond.");
 
 if ( "Help file '<script>x</script>' could not be found!" >< res[2] )
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}
