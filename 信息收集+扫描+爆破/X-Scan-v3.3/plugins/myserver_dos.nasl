#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11770);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(7917, 8120);
 script_xref(name:"OSVDB", value:"2273");
 script_xref(name:"OSVDB", value:"53793");
 
 script_name(english:"MyServer <= 0.4.2 Multiple Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyServer 0.4.2 or older. 

There are flaws in this software which may allow an attacker
to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0047.html" );
 script_set_attribute(attribute:"solution", value:
"Upograde to MyServer 4.3 as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of MyServer");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner) exit(0);
if(egrep(pattern:"^Server:MyServer 0\.([0-3]\.|4\.[0-2])[^0-9]", string:banner))
	{
	  security_warning(port);
	}


