#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10040);
 script_bugtraq_id(3885);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2002-0128");
 script_xref(name:"OSVDB", value:"34");
 
 script_name(english:"Sambar Server cgitest.exe Remote Overflow");
 script_summary(english:"Checks for the /cgi-bin/cgitest.exe buffer overrun");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a vulnerable version of Sambar Server, a\n",
     "web server and web proxy.\n\n",
     "There is a remote buffer overflow vulnerability in 'cgitest.exe'.\n",
     "A remote attacker could use this to crash the web server, or\n",
     "potentially execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-04/1102.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove the affected file from /cgi-bin."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

flag = 0;
directory = "";

foreach dir (cgi_dirs())
{
 if(is_cgi_installed3(item:string(dir, "/cgitest.exe"), port:port))
 {
  flag = 1;
  directory = dir;
  break;
 } 
}

if(!flag)exit(0);
data = string(directory, "/cgitest.exe");
user_agent = make_array("User-Agent", crap(2600));
r = http_send_recv3(method:"GET", item:data, port:port, add_headers:user_agent);
if(!r)security_hole(port);

