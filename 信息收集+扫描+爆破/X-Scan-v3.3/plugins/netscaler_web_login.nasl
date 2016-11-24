# netscaler_web_login.nasl
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
    script_id(29223);
    script_version("$Revision: 1.4 $");

    script_name(english:"NetScaler Web Management Successful Authentication");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote web management interface." );
 script_set_attribute(attribute:"description", value:
"Nessus successfully logged into the remote Citrix NetScaler web
management interface using the supplied credentials and stored the
authentication cookie for later use." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

    script_summary(english:"Logs into NetScaler web management interface");
    script_family(english:"Web Servers");
script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (c) 2007-2009 nnposter");
    script_dependencies("logins.nasl","netscaler_web_detect.nasl");
    script_require_keys("www/netscaler","http/login");
    script_require_ports("Services/www",80);
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);
if (!get_kb_item("http/login"))    exit(0);


include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

url="/ws/login.pl?"
    + "username="+urlencode(str:get_kb_item("http/login"))
    +"&password="+urlencode(str:get_kb_item("http/password"))
    +"&appselect=stat";

resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
if (!resp) exit(0);

cookie=egrep(pattern:"^Set-Cookie:",string:resp,icase:TRUE);
if (!cookie) exit(0);

cookie=ereg_replace(string:cookie,pattern:'^Set-',replace:" ",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:';[^\r\n]*',replace:";",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:'\r\nSet-Cookie: *',replace:" ",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:'; *(\r\n)',replace:"\1",icase:TRUE);
if (cookie!~" ns1=.* ns2=") exit(0);

set_kb_item(name:"/tmp/http/auth/"+port,value:cookie);
security_note(port);
