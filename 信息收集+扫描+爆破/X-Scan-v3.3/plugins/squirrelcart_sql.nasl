#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(17652);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2005-0962");
 script_bugtraq_id(12944);
 script_xref(name:"OSVDB", value:"15124");

 script_name(english:"Squirrelcart index.php Multiple Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SquirrelCart, a shopping cart program
written in PHP. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary SQL commands, which may in turn be used to gain
administrative access on the remote host. 

SquirrelCart 1.5.5 and prior versions are affected by this flaw." );
 script_set_attribute(attribute:"see_also", value:"http://www.ldev.com/forums/showthread.php?t=1860" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelCart 1.6.0 or download a patch from
SquirrelCart.com." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"SQL Injection in Squirrelcart");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  local_var req, buf;
  global_var port;

  req = http_get(item:dir + "/store.php?crn=42'&action=show&show_products_mode=cat_click", port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(buf == NULL)exit(0);

  if('SELECT Table_2 FROM REL_SubCats__Cats WHERE Table_2 = ' >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) check( dir:dir );
