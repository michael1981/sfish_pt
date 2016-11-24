#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10583);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2001-0436", "CVE-2001-0437");
 script_bugtraq_id(2611);
 script_xref(name:"OSVDB", value:"3861");
 script_xref(name:"OSVDB", value:"3862");
 script_xref(name:"OSVDB", value:"3867");

 script_name(english:"DCForum dcboard.cgi Multiple Vulnerabilities");
 script_summary(english:"Checks for the presence of /cgi-bin/dcforum");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server is hosting a CGI known to have multiple\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The DCForum dcboard.cgi script is installed. This CGI has some well\n",
     "known security flaws, including one that lets an attacker execute\n",
     "arbitrary commands with the privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2001-04/0269.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remote this script from /cgi-bin."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
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

port = get_http_port(default:80);
dirs = list_uniq(make_list('/dcforum', cgi_dirs()));

foreach dir (dirs)
{
 url = string(
   dir,
   "/dcforum.cgi?az=list&forum=../../../../../../../etc/passwd%00"
 );
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))	
 {
 	security_hole(port);
 	exit(0);
 }
}



