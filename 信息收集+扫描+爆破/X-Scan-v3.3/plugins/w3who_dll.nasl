# 
# (C) Nicolas Gregoire <ngregoire@exaprobe.com>
#
# Rewritten by Tenable Network Security
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, changed family (6/1/09)


include("compat.inc");

if(description)
{
 script_id(15910);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1133", "CVE-2004-1134");
 script_bugtraq_id(11820);
 script_xref(name:"OSVDB", value:"12256");
 script_xref(name:"OSVDB", value:"12257");
 script_xref(name:"OSVDB", value:"12258");

 script_name(english:"Microsoft W3Who ISAPI w3who.dll Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The Windows 2000 Resource Kit ships with a DLL that displays the browser 
client context. It lists security identifiers, privileges and $ENV variables. 

Nessus has determined that this file is installed on the remote host.

The w3who.dll ISAPI may allow an attacker to execute arbitrary commands 
on this host, through a buffer overflow, or to mount XSS attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-12/0157.html" );
 script_set_attribute(attribute:"solution", value:
"Delete this file" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the presence of w3who.dll");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Nicolas Gregoire <ngregoire@exaprobe.com>");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

req  = http_get(item:"/scripts/w3who.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);

if ("Access Token" >< res && "Environment variables" >< res)
{
 req  = http_get(item:"/scripts/w3who.dll?bogus=<script>alert('Hello')</script>", port:port);
 res  = http_keepalive_send_recv(port:port, data:req);

 if ("<script>alert('Hello')</script>" >< res)
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
