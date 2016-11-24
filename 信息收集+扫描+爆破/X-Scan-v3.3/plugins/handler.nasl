#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10100);
 script_bugtraq_id(380);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0148");
 script_xref(name:"OSVDB", value:"85");

 script_name(english:"IRIX handler CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/handler");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'handler' cgi is installed. This CGI has a well known security 
flaw that lets anyone execute arbitrary commands with the 
privileges of the http daemon (root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"ftp://patches.sgi.com/support/free/security/advisories/19970501-02-PX" );
 script_set_attribute(attribute:"solution", value:
"Remove the script from /cgi-bin or change the permissions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");
port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/handler/blah%3Bid|?data=Download", port:port);
if (isnull(res)) exit(1, "The web server did not respond to the request.");
if (("uid=" >< res[2]) && ("gid=" >< res[2])) security_hole(port:port);
