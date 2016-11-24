#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, changed family (9/3/09)


include("compat.inc");

if(description)
{
 script_id(17244);
 script_version("$Revision: 1.6 $");
 
 script_name(english:"Trend Micro IMSS Console Management Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote hsot apepars to be running a Security Suite with a web
interface." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to run Trend Micro Interscan Messaging 
Security  Suite, connections are allowed to the web console 
management.

Make sure that only authorized hosts can connect to this service, as
the information of its existence may help an attacker to make more 
sophisticated attacks against the remote network." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english:"Checks for Trend Micro IMSS web console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  req = http_get(item:"/commoncgi/servlet/CCGIServlet?ApHost=PDT_InterScan_NT&CGIAlias=PDT_InterScan_NT&File=logout.htm", port:port);
 
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);
 if("<title>InterScan Messaging Security Suite for SMTP</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
