#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10656);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0304");
 script_bugtraq_id(2384);
 script_xref(name:"OSVDB", value:"544");
 
 script_name(english:"Resin Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a directory traversal attack.");
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on the remote server by
prepending /\../\../ to the file name." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your version of Resin in 1.2.3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();
 
 script_summary(english:"request \..\..\file.txt");
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080); # by default, Resin listens on this port, not 80

r = http_send_recv3(method: "GET", port: port, item: '/\\../readme.txt');
if ("This is the README file for Resin(tm)" >< r[0]+r[1]+r[2])
   security_warning(port);

