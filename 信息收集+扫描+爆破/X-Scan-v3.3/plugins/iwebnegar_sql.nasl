#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15972);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-1402");
 script_bugtraq_id(11946);
 script_xref(name:"OSVDB", value:"12417");

 script_name(english:"iWebNegar Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running iWebNegar, a web log application
written in PHP. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary SQL commands and in turn gain administrative access to the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0175.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/index.php?string='", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);
  if ("iWebNegar" >< res &&
     egrep(pattern:"mysql_fetch_array\(\).*MySQL", string:res) ) 
	{
	  security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  exit(0);
	}
 }
