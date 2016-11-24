#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11735);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0436", "CVE-2003-0437");
 script_bugtraq_id (7865, 7866); 
 script_xref(name:"OSVDB", value:"11872");
 script_xref(name:"OSVDB", value:"11873");
 
 script_name(english:"Mnogosearch search.cgi Multiple Parameter Remote Overflows");
 script_summary(english:"Checks for search.cgi");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has multiple buffer overflow\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The mnogosearch search.cgi CGI is installed on the remote web server.\n",
     "Older versions of this software have multiple buffer overflow\n",
     "vulnerabilities.  A remote attacker could exploit these issues to\n",
     "execute arbitrary code.\n\n",
     "Nessus only detected the presence of this CGI, and did not attempt\n",
     "to determine whether or not it is vulnerable."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Disable this CGI if it is not being used, or upgrade to the\n",
     "latest version."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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

if (report_verbosity < 2) exit(0);

port = get_http_port(default:80);

foreach d (cgi_dirs()) {
 url = d + "/search.cgi";
 res = http_send_recv3(method:"GET", item:url, port:port);
 if( "mnoGoSearch" >< res[2] ) {
 	security_hole(port);
	exit(0);
	}
}
