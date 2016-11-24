#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10195);
 script_version ("$Revision: 1.32 $");

 script_name(english:"HTTP Proxy Open Relay Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web proxy server accepts requests." );
 script_set_attribute(attribute:"description", value:
"The remote web proxy accepts unauthenticated HTTP requests from the
Nessus scanner.  By routing requests through the affected proxy, a
user may be able to gain some degree of anonymity while browsing web
sites, which will see requests as originating from the remote host
itself rather than the user's host." );
 script_set_attribute(attribute:"solution", value:
"Make sure access to the proxy is limited to valid users / hosts." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english: "Determines if we can use the remote web proxy");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Firewalls");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/http_proxy", 3128, 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:3128);
ports = add_port_in_list(list:ports, port:8080);
ports = add_port_in_list(list:ports, port:80);


foreach port (ports)
{
  rq = http_mk_proxy_request(method: "GET", scheme: "http", host: "www.nessus.org", item: "/check_proxy.html", version: 10);
  r = http_send_recv_req(port: port, req: rq);
  if (! isnull(r) && r[0] =~ "^HTTP/1\.[01] 200 " && "@NESSUS:OK@" >< r[2])
    {
      security_note(port);
      set_kb_item(name:"Proxy/usage", value:TRUE);
      set_kb_item(name:"Services/http_proxy", value:port);
    }
}

