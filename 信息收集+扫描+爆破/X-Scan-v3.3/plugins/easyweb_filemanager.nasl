#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(13845);
 script_cve_id("CVE-2004-2047");
 script_bugtraq_id(10792);
 script_xref(name:"OSVDB", value:"8193");
 script_version("$Revision: 1.10 $");

 script_name(english:"EasyWeb FileManager pathtext Traversal Arbitrary File/Directory Access");
 script_summary(english:"Determines if EasyWeb FileManager is present");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a directory traversal\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of the EasyWeb FileManager module\n",
     "which is vulnerable to a directory traversal attack.\n\n",
     "An attacker may use this flaw to read arbitrary files on the remote\n",
     "server by sending malformed requests like :\n\n",
     "/index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../file\n\n",
     "Note that this might be a false positive, since an attacker would need\n",
     "credentials to exploit this flaw."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0010.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2004-07/0289.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this module."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 url = string(dir, "/index.php?module=ew_filemanager&type=admin&func=manager");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res)) exit(0);
 
 if( egrep(pattern:"_NOAUTH", string:res[2]) )
 {
    	security_warning(port);
	exit(0);
 }
}
