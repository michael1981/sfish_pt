#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10291);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0177");
 script_xref(name:"OSVDB", value:"229");

 script_name(english:"O'Reilly WebSite uploader.exe Arbitrary File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote web server contains a CGI script named 'uploader.exe' in
'/cgi-win'.  Versions of O'Reilly's Website product before 1.1g
included a script with this name that allows an attacker to upload
arbitrary CGI and then execute them." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b667852" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bca098f" );
 script_set_attribute(attribute:"solution", value:
"Verify that the affected script does not allow arbitrary uploads and
remove it if it does." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-win/uploader.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
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
cgi = "/cgi-win/uploader.exe";
res = is_cgi_installed3(item:cgi, port:port);
if(res)security_hole(port);

