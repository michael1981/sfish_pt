#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16319);
 script_bugtraq_id(12456);
 script_xref(name:"OSVDB", value:"13567");
 script_xref(name:"OSVDB", value:"13568");
 script_xref(name:"OSVDB", value:"13569");
 script_xref(name:"OSVDB", value:"13570");
 script_xref(name:"OSVDB", value:"13571");
 script_xref(name:"OSVDB", value:"13572");
 
 script_version ("$Revision: 1.9 $");
 script_name(english:"Chipmunk Forum Multiple SQL Injections");
 script_summary(english:"Checks if Chipmunk forum is vulnerable to a SQL injection attack");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has a SQL injection\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running Chipmunk, a web-based forum written\n",
     "in PHP.\n\n",
     "The remote version of this software is affected by several SQL\n",
     "injection vulnerabilities that may allow an attacker to execute\n",
     "arbitrary SQL statements on the remote SQL database."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/1016.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Chipmunk version 1.3 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if (! can_host_php(port:port)) exit(0);

if (wont_test_cgi(port: port)) exit(0);

foreach dir ( cgi_dirs() )
{
  r = http_send_recv3(port: port, method: 'POST', 
   data: "email='&submit=submit", item: dir + "/getpassword.php", 
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );
  if (isnull(r)) exit(0);
  if("<link rel='stylesheet' href='style.css' type='text/css'>Could not get info" >< r[2])
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
