#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15934);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2496");
 script_bugtraq_id(11877);
 script_xref(name:"OSVDB", value:"12350");
 
 script_name(english:"OpenText FirstClass HTTP Daemon /Search Large Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a denila of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenText FirstClass, a web based unified
messaging system. 

The remote version of this software is vulnerable to an unspecified
Denial of Service attack which may allow an attacker to disable this
service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0321.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version newer than FirstClass OpenText 8.0.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );


script_end_attributes();

 
 script_summary(english:"Checks for FirstClass");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(banner)
{ 
  if(egrep(pattern:"^Server: FirstClass/([0-7]\.|8\.0[^0-9])", string:banner))
   	security_hole(port);
}
