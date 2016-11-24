#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10149);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1527");
 script_bugtraq_id(816);
 script_xref(name:"OSVDB", value:"115");

 script_name(english:"Sun NetBeans Java IDE HTTP Server IP Restriction Bypass Arbitrary File/Directory Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NetBeans (recently renamed to
Forte') Java IDE. There is a bug in this version that allows
anyone to browse the files on this system." );
 script_set_attribute(attribute:"solution", value:
"Set the HTTP server 'Enable' to FALSE in Project settings" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"determines whether the remote root directory is browsable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80, 8082);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function netbeans(port)
{
local_var data, data_low, seek;
if(get_port_state(port))
{
  data = http_get_cache(item:"/", port:port);
  data_low = tolower(data);
  seek = "<title>index of /</title>";
  if(seek >< data_low)
  {
   if("netbeans" >< data_low) { 
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/content/directory_index', value: '/');
	exit(0);
	}
   }
 }
}

#
# NetBeans might be running on another port.
# 
if ( thorough_tests ) netbeans(port:8082);

port = get_http_port(default:80);
if(!port)exit(0);
if (port != 8082 || ! thorough_tests) netbeans(port:port);
