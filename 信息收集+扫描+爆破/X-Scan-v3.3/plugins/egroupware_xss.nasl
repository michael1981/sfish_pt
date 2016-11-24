#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14358);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-1467");
 script_bugtraq_id(11013);
 script_xref(name:"OSVDB", value:"9134");
 script_xref(name:"OSVDB", value:"9136");
 script_xref(name:"OSVDB", value:"9137");
 script_xref(name:"OSVDB", value:"9138");
 
 script_name(english:"eGroupWare <= 1.0.00.003 Multiple Module XSS");
 script_summary(english:"Checks for the presence of an XSS bug in EGroupWare");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a cross-site\n",
     "scripting vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote version of eGroupware is vulnerable to a cross-site\n",
     "scripting attack.  This could allow a remote attacker to steal the\n",
     "cookies of a legitimate user by tricking them into clicking a\n",
     "maliciously crafted URL.\n\n",
     "eGroupware reportedly has other cross-site scripting vulnerabilities,\n",
     "though Nessus has not tested for those issues."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0302.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to eGroupware 1.0.0.004 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("egroupware_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

kb  = get_kb_item("www/" + port + "/egroupware");
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb);
loc = stuff[2];

test_cgi_xss(port: port, dirs: make_list(loc), cgi: "/index.php",
 qs: "menuaction=calendar.uicalendar.day&date=20040405<script>foo</script>",
 pass_str: '<script>foo</script>');

