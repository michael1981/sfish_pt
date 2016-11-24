#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11698);
 script_version("$Revision: 1.17 $");
 script_bugtraq_id(7804);
 script_xref(name:"OSVDB", value:"53063");

 script_name(english:"Xpressions Interactive Multiple Products login.asp SQL Injection");
 script_summary(english:"Attempts SQL Injection");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host has a web vulnerability that can allow an attacker\n",
     "to manage the website with administrative privileges."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running a software suite (truConnect,\n",
     "FlowerLink, eVision, or Website Integration) from Xpressions Software.\n",
     "\n",
     "The software in question has multiple SQL injection vulnerabilities\n",
     "that could allow an attacker to gain administrative access.  This\n",
     "could lead to the exposure of user passwords and credit card data."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-06/0026.html"
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
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


function check(req)
{
  local_var buf, r, variables;

  variables = string("c=1&ref=&Uname=nessus&Upass='&submit1=Submit");
  r = http_send_recv3(method: "POST", item: req, version: 11, port: port,
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
   data: variables);

  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);

  if("Microsoft OLE DB Provider for SQL Server" >< buf && "error '" >< buf)
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}


foreach dir ( cgi_dirs() )
{
  if ( is_cgi_installed3(item:dir + "/manage/login.asp", port:port) ) check(req:dir + "/manage/login.asp");
}
