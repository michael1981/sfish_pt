#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(12038);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-0239");
 script_bugtraq_id(9557);
 script_xref(name:"OSVDB", value:"15100");

 script_name(english:"Photopost PHP Pro photo Parameter SQL Injection"); 
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a PHP application that is affected by a\n",
   "SQL injection vulnerability."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The version of Photopost PHP Pro installed on the remote host fails to\n",
   "sanitize user-supplied input to the 'photo' parameter of the\n",
   "'showphoto.php' script before using it in a database query.  An\n",
   "unauthenticated attacker may be able to exploit this issue to uncover\n",
   "sensitive information, modify data, launch attacks against the\n",
   "underlying database, etc."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0053.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Contact the vendor for a patch which was reportedly released to\n",
   "address this issue."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_summary(english:"SQL Injection");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("photopost_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 dir = matches[2];

 req = http_get(item:dir + "/showphoto.php?photo=123'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( isnull(res) ) exit(0);
 
 if ("id,user,userid,cat,date,title,description,keywords,bigimage,width,height,filesize,views,medwidth,medheight,medsize,approved,rating" >< res ) {
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
}
