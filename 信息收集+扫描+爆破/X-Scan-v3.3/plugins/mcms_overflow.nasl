#
# (C) Tenable Network Security, Inc.
#

# Supercedes MS02-010
#
# Thanks to Dave Aitel for the details.


include("compat.inc");

if(description)
{
 script_id(11313);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2002-0700", "CVE-2002-0718", "CVE-2002-0719");
 script_bugtraq_id(5421, 5422, 5420);
 script_xref(name:"OSVDB", value:"4862");
 script_xref(name:"OSVDB", value:"4914");
 script_xref(name:"OSVDB", value:"4915");
 script_xref(name:"IAVA", value:"2002-B-0007");
 
 script_name(english:"Microsoft Content Management Server (MCMS) 2001 Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote hosts." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Content Management Server.

There is a buffer overflow in the Profile Service which may
allow an attacker to execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"See http://www.microsoft.com/technet/security/bulletin/ms02-041.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Checks for the presence of MCMS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
if (http_is_dead(port: port)) exit(0);

if(!is_cgi_installed3(port:port, item:"/NR/System/Access/ManualLoginSubmit.asp")) exit(0);

payload = 'NR_DOMAIN=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_DOMAIN_LIST=WinNT%3A%2F%2F0AG4ZA0SR80BCRG&NR_USER=Administrator&NR_PASSWORD=asdf&submit1=Continue&NEXTURL=%2FNR%2FSystem%2FAccess%2FDefaultGuestLogin.asp';

r = http_send_recv3( port: port, method: 'POST', 
    		     item: "/NR/System/Access/ManualLoginSubmit.asp", 
		     data: payload, 
		     add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

if (isnull(r) || ! r[0]) { security_hole(port); exit(0); }
if (r[0] =~ "^HTTP/[0-9]\.[0-9] 500 ") security_hole(port);
