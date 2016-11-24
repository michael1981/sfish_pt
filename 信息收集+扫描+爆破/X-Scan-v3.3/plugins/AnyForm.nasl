#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10277);
 script_bugtraq_id(719);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0066");
 script_xref(name:"OSVDB", value:"1116");

 script_name(english:"AnyForm CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of AnyForm2");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected a remote
command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CGI 'AnyForm2' is installed on the remote web server. Old versions
of this CGI have a well known security flaw that lets anyone execute
arbitrary commands with the privileges of the http daemon (root or
nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1995_3/0083.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed3(item:"AnyForm2", port:port);
if( res )security_hole(port);
