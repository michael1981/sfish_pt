#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if(description)
{ 
 script_id(10192);
 script_version ("$Revision: 1.17 $");
 
 script_name(english: "HTTP Proxy CONNECT Request Relaying");
 
 script_set_attribute(attribute:"synopsis", value:
"The HTTP proxy can be used to establish interactive sessions." );
 script_set_attribute(attribute:"description", value:
"The proxy allows the users to perform CONNECT requests such as

	CONNECT http://cvs.nessus.org:23 

This request gives the person who made it the ability to have an 
interactive session with a third-party site.

This problem may allow attackers to bypass your firewall by 
connecting to sensitive ports such as 23 (telnet) via the proxy, or it
may allow internal users to bypass the firewall rules and connect to 
ports or sites they should not be allowed to. 

In addition, your proxy may be used to perform attacks against
other networks." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy so that it refuses CONNECT requests." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english: "Determines if we can use the remote web proxy against any port");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "Firewalls");
 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

proxy_use = get_kb_item("Proxy/usage");
if (! proxy_use) exit(0);

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (! get_port_state(port)) exit(0);


rq = http_mk_proxy_request(method: "CONNECT", host: get_host_name(), port: 1234, version: 10);
r = http_send_recv_req(port: port, req: rq);
if (isnull(r)) exit(0);

if (r[0] =~ "^HTTP1\.[01] (200|503) ") security_note(port);

