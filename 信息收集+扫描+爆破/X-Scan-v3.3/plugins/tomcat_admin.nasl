#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10477);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0672");
 script_bugtraq_id(1548);
 script_xref(name:"OSVDB", value:"376");

 script_name(english:"Apache Tomcat contextAdmin Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to access arbitrary files from the 
remote system." );
 script_set_attribute(attribute:"description", value:
"The page  /admin/contextAdmin/contextAdmin.html
can be accessed.

This allows an attacker to add context to your Tomcat
web server, and potentially to read arbitrary files 
on this server." );
 script_set_attribute(attribute:"solution", value:
"restrict access to /admin or remove this
context, and do not run TomCat as root." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /admin");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

res = http_send_recv3(method:"GET", item:"/admin/contextAdmin/contextAdmin.html", port:port);
if(ereg(pattern:"HTTP/[0-9].[0-9] 200 ", string: res[0]))
{
  if("Servlet-Engine: Tomcat" >< res[1])
  {
   security_hole(port);
  }
}
