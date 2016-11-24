#
# This script was written by David Maciejak <david dot maciejak at gmail dot com>
#


include("compat.inc");

if(description)
{
script_id(25402);

script_cve_id("CVE-2007-2964");
script_bugtraq_id(24233);
script_xref(name:"OSVDB", value:"36723");

script_version("$Revision: 1.5 $");
script_name(english:"F-Secure Policy Manager Server fsmsh.dll module DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is an F-Secure Policy Manager Server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version a F-Secure Policy Manager Server
which is vulnerable to a denial of service. 

A malicious user can forge a request to query a MS-DOS device name
through the 'fsmsh.dll' CGI module, which will prevent legitimate
users from accessing the service using the Manager Console." );
 script_set_attribute(attribute:"see_also", value:"http://www.f-secure.com/security/fsc-2007-4.shtml" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to F-Secure Policy Manager Server 7.01 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

script_summary(english:"Detects F-Secure Policy Manager DoS flaw");

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2009 David Maciejak");
 script_family(english:"Denial of Service");

 script_dependencies("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

os = get_kb_item("Host/OS/icmp");
if (!os || "Windows" >!< os) exit(0);

port = get_http_port(default:80);
if (!port) exit(0);
if(!get_port_state(port))exit(0);

# only check FSMSH.DLL version
buf = http_get(item:"/fsms/fsmsh.dll?FSMSCommand=GetVersion", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if (r =~ "^([0-6]\.|7\.00)") security_warning(port);
