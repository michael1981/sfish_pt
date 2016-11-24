#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12032);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2007-1156");
 script_bugtraq_id(9537);
 script_xref(name:"OSVDB", value:"33141");
 
 script_name(english:"JBrowser Admin Authentication Bypass Vulnerability");
 script_summary(english:"Checks JBrowser");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an authentication\n",
     "bypass vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running JBrowser - a PHP script designed to browse\n",
     "photos and files in a remote directory.\n\n",
     "It is possible to access the admin panel by directly requesting\n",
     "'/_admin/'.  A remote attacker could exploit this to perform\n",
     "administrative actions without authentication."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2007-02/0422.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2007-02/0472.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
 req = string(dir,"/_admin/");
 res = http_send_recv3(method:"GET", item:req, port:port);
 if (isnull(res)) exit(1, "The server didn't respond.");

 if(egrep(pattern:'.*form enctype="multipart/form-data" action="upload.php3*" method=POST>', string:res[2])){
 	security_hole(port);
	exit(0);
	}
}
