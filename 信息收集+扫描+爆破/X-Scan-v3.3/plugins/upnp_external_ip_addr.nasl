#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35708);
 script_version("$Revision: 1.2 $");
 script_name(english: "UPnP Internet Gateway Device (IGD) External IP Address Reachable");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to read the external IP addres of the remote router.");
 script_set_attribute(attribute:"description", value:
"According to UPnP data, the remote device is a NAT router that supports
the Internet Gateway Device (IGD) Standardized Device Control Protocol.

Nessus was able to get the external IP address of the device.");
 script_set_attribute(attribute:"see_also", value:
"http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value: "Disable IGD or restrict access to trusted networks.");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_end_attributes();
 script_summary(english: "Call GetExternalIPAddress on UPnP IGD router");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('upnp_func.inc');

port = get_kb_item('upnp/www');
if (! port) exit(0);

gd = get_kb_item('upnp/'+port+'/devdescr');
if (! gd) exit(0);

foreach sv (make_list("WANIPConnection", "WANPPPConnection"))
{
  url = upnp_find_service(xml: gd, svc: sv);
  if (! url) continue;

  testport = rand() % 32768 + 32768;

  fields = make_array();

  s = 'urn:schemas-upnp-org:service:'+sv+':1';
  act = 'GetExternalIPAddress';
  rq = upnp_make_soap_req(port: port, url: url, action: act, fields: fields, svc: s);
  r = http_send_recv_req(port: port, req: rq);

  if (isnull(r)) continue;

  if (r[0] !~ '^HTTP/1\\.[01] 200 ') continue;

  ip = NULL;  
  p = strstr(r[2], "<NewExternalIPAddress>");
  if (! isnull(p))
  {
    r = eregmatch(string: p, pattern: "<NewExternalIPAddress>([0-9.]+)</NewExternalIPAddress>");
    if (! isnull(r)) ip = r[1];
  }
  if (isnull(ip))
   security_note(port: port, extra: "
The device answers to GetExternalIPAddress, but Nessus could not
extract the IP address from the answer.
");
  else
  {
    set_kb_item(name: "upnp/external_ip_addr", value: ip);
    security_note(port: port, extra: strcat(
'\nThe external IP address of this device is : ', ip, '\n'));
  }
  break;
}
