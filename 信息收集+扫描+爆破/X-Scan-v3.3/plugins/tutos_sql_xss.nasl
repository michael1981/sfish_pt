#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14784);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2003-0481", "CVE-2004-2161", "CVE-2004-2162");
 script_bugtraq_id(8011, 8012, 11221);
 script_xref(name:"OSVDB", value:"2192");
 script_xref(name:"OSVDB", value:"5327");
 script_xref(name:"OSVDB", value:"10164");

 script_name(english:"TUTOS < 1.2 Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Tutos, an open-source team 
organization software package written in PHP.

The remote version of this software is vulnerable to multiple 
input validation flaws which may allow an authenticated user to 
perform a cross site scripting attack or a SQL injection against 
the remote service." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tutos-1.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the version of Tutos");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_php(port:port) ) exit(0,"The remote web server does not support PHP.");

foreach dir (make_list( cgi_dirs() )) 
 {
   res = http_send_recv3(method:"GET", item:dir + "/php/mytutos.php", port:port);
   if (isnull(res)) exit(0,"Null response to mytutos.php request.");
  if ( '"GENERATOR" content="TUTOS' >< res[2] &&
       egrep(pattern:".*GENERATOR.*TUTOS (0\..*|1\.[01]\.)", string:res[2]) )
	{
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 exit(0);
	}
 }
