#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(16206);
 script_bugtraq_id(12154);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-1061");
 script_xref(name:"OSVDB", value:"12699");

 script_name(english:"Bugzilla Internal Error Response XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Bugzilla, a web-based bug tracking system.

The remote Bugzilla installation, according to its version number
is vulnerable to a cross-site scripting attack when rendering internal
errors containing user-supplied input." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla 2.18.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for the presence of bugzilla";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("bugzilla_detect.nasl");
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

version = get_kb_item(string("www/", port, "/bugzilla/version"));
if(!version)exit(0);


if(ereg(pattern:"(1\..*)|(2\.(0\..*|1[0-7]\..*))", string:version)) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      } 
