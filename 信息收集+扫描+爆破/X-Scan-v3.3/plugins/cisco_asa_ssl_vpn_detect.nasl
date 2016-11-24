#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(42796);
  script_version("$Revision: 1.1 $");

  script_name(english:"CISCO ASA SSL VPN Detection");
  script_summary(english:"Looks for the login screen");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is an SSL VPN Server.'
  );

  script_set_attribute(
    attribute:'description',
    value:"
The remote host is a Cisco Adaptive Security Appliance (ASA) running
an SSL VPN server.

Make sure the use of this device is authorized by your company
policy."
  );

  script_set_attribute(
    attribute:'solution',
    value: "n/a"
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_set_attribute(
    attribute:'plugin_publication_date', 
    value:'2009/11/12'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/www", 443);
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');



port = get_http_port(default:443);

init_cookiejar();
r = http_send_recv3(method:"GET", port:port, item:"/+CSCOE+/win.js");
if (isnull(r)) exit(1, "The web server failed to respond.");

if ( r[0] =~ "^HTTP/[0-9.]+ 200 " && !isnull(r[2]) && "CSCO_WebVPN" >< r[2] )
{
 r = http_send_recv3(method:"GET", port:port, item:"/+CSCOE+/logon.html");
 if (isnull(r)) exit(1, "The web server failed to respond.");

 if ( r[0] =~ "^HTTP/[0-9.]+ 200 " )
 {
  register_service(port:port, proto:"cisco-ssl-vpn-svr");
  security_note(port:port, extra:'
The login page for the remote VPN can be accessed using the following
URL :

  ' + build_url(port:port, qs:"/+CSCOE+/logon.html"));
 }
}

