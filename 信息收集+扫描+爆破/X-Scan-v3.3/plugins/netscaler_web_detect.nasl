# netscaler_web_detect.nasl
# GPLv2
#
# History:
#
# 1.00, 11/21/07
# - Initial release

# Changes by Tenable:
# - Revised plugin title (9/23/09)


include("compat.inc");

if (description)
    {
    script_id(29222);
    script_version("$Revision: 1.3 $");
    
    script_name(english:"NetScaler Web Management Interface Detection");

 script_set_attribute(attribute:"synopsis", value:
"A Citrix NetScaler web management interface is running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Citrix NetScaler, an appliance for web
application delivery, and the remote web server is its management
interface." );
 script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/lang/English/ps2/index.asp" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

    script_summary(english:"Detects NetScaler web management interface");
    script_family(english:"Web Servers");
script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (c) 2007-2009 nnposter");
    script_dependencies("find_service1.nasl","httpver.nasl");
    script_require_ports("Services/www",80);
    exit(0);
    }


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0);

resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:"/index.html",port:port),
                              embedded:TRUE);
if (!resp) exit(0);

match1=egrep(pattern:"<title>Citrix Login</title>",string:resp,icase:TRUE);
match2=egrep(pattern:'action="/ws/login\\.pl"',string:resp,icase:TRUE);
if (!match1 || !match2) exit(0);

replace_or_set_kb_item(name:"www/netscaler",value:TRUE);
replace_or_set_kb_item(name:"www/netscaler/"+port,value:TRUE);
replace_or_set_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

security_note(port);
