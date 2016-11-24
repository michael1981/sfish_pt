#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10037);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0079");
 script_xref(name:"OSVDB", value:"31");
 script_bugtraq_id(936);

 script_name(english:"CERN httpd Virtual Web Path Disclosure");
 script_summary(english:"Attempts to find the location of the remote web root");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running CERN httpd.  It was possible to\n",
     "get the physical location of a virtual web directory by issuing the\n",
     "request :\n\n",
     "  GET /cgi-bin/ls HTTP/1.0\n\n",
     "A remote attacker could use this information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0222.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "CERN httpd is no longer maintained.  Switch to using an actively\n",
     "supported web server." 
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/cern");
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
  d = string(dir, "/ls");
  r = http_send_recv3(method:"GET", item:d, port:port);
  if( r == NULL ) exit(0);
  r = tolower(r);
  if(" neither '/" >< r){
  	security_warning(port);
	exit(0);
	}
}

