#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10246);
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-2000-0213");
 script_bugtraq_id(1002);
 script_xref(name:"OSVDB", value:"194");
 script_xref(name:"OSVDB", value:"5802");
 
 script_name(english:"Sambar Server Multiple Script Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"At least one of these CGI scripts is installed :

	hello.bat
	echo.bat
	
They allow any attacker to execute commands with the privileges of the web 
server process." );
 script_set_attribute(attribute:"solution", value:
"Delete all the *.bat files from your cgi-bin/ directory" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/{hello,echo}.bat");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default: 80);

if (is_cgi_installed3(item:"hello.bat", port:port) ||
    is_cgi_installed3(item:"echo.bat", port:port))
  security_hole(port);

