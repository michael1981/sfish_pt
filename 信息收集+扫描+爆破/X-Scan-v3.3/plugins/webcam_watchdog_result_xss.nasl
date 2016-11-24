#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14186);
 script_cve_id("CVE-2004-2528");
 script_bugtraq_id(10837);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8260");
 }
 script_version ("$Revision: 1.10 $"); 
 name["english"] = "WebCam Watchdog sresult.exe XSS";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WebCamSoft's watchdog software.  There is a
CGI script included in this software suite ('sresult.exe') that fails
to sanitize user-supplied input to the 'cam' parameter before using it
to generate dynamic output.  An attacker may exploit this issue to
steal cookie-based credentials from a legitimate user of this site." );
 script_set_attribute(attribute:"see_also", value:"http://members.lycos.co.uk/r34ct/main/Webcam_watchdog_401a.txt" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of an XSS bug in watchdog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss(port: port, cgi: "/sresult.exe", qs: "cam=<script>foo</script>",
 pass_str: "<script>foo</script>");
