#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(12225);
  script_version ("$Revision: 1.9 $");

  script_name(english:"Web Server Reverse Proxy Detection");
  script_summary(english:"Web Server reverse proxy bug");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote Web server seems to allow any anonymous user
to use it as a reverse proxy.  This may expose internal
services to potential mapping and, henceforth, compromise."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable or restrict access the reverse proxy."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.sans.org/reading_room/whitepapers/webservers/a_reverse_proxy_is_a_proxy_by_any_other_name_302?show=302.php&cat=webservers'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

req = http_get(item:"/images", port:port);
soc = http_open_socket(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
res = http_recv_headers2(socket:soc);
close (soc);



# Step[0]
# OK, so there are some reqs before we go any further
# namely, 0) The webserver needs to respond ;-)
# 1) we need a 302 redirect and
# 2) the redirect needs to be to an IP addr and
# 3) the redirect needs to be to an IP other than this webserver

if(res == NULL || "302" >!< res ) exit(0);
myloc = strstr(res, string("Location: http://") ) ;
myloc2 = strstr(res, string("/images"));
url = strstr(myloc - myloc2, "http");
if ( get_host_name() >< url ) exit(0);
if ( get_host_ip() >< url ) exit(0);

if (! egrep(string:url, pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") ) exit(0);



# Step[1]
# initial flagging for IP found
url = ereg_replace(pattern:"http://", replace:"", string:url);
mymsg = string("The remote server seems to divulge information regarding an internal
or trusted IP range.  Specifically, the Location field within the return header
points to the following network: ", url, "\n");

security_warning(port:port, data:mymsg);


# Step[2]
# onward and upward
# one last fp check...let's make sure the server doesn't just respond
# with 200 OK + default page for any bogus request

soc = http_open_socket(port);
if ( ! soc ) exit(0);
nofp = http_get(port:port, item:"http://0.0.0.0:31445/");
send(socket:soc, data:nofp);
rep = recv_line(socket:soc, length:1024);
if ("200 OK" >< rep ) exit(0);
close(soc);


# Step[3] ... *finally* let's test the server for proxying capabilities
# whodat say whodat when I say whodat?
# so, we'll roll through the /24 denoted in host location, requesting
# http://<IP addr>:139/ ... the reverse proxy should map out the internal
# hosts running netbios ... we can do all this on one HTTP session (hopefully)

octets = split(get_host_ip(), sep:".", keep:0);

for (i=1; i<256; i++) {
    whodat = string("http://");
    count=0;
    foreach v (octets) {
        count++;
        if (count == 4) whodat += string(i, ":139/");
        else whodat += string(v,".");
    }
    req = string("GET ", whodat, " HTTP/1.0\r\n\r\n");
    rep = http_keepalive_send_recv(port:port, data:req);
    if ( "200 OK" >< rep ) {
        security_warning(port);
        exit(0);
    }
}



