#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35707);
 script_version("$Revision: 1.2 $");
 script_name(english: "UPnP Internet Gateway Device (IGD) Port Mapping Manipulation");

 script_set_attribute(attribute:"synopsis", value:"It was possible to add port redirections to the remote router.");
 script_set_attribute(attribute:"description", value:
"According to UPnP data, the remote device is a NAT router which supports
the Internet Gateway Device (IGD) Standardized Device Control Protocol.

Nessus was able to add 'port mappings' that redirect ports from the 
device external interface to the scanner address.

A malicious Flash animation could do the same.");
script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/flash-upnp-attack-faq/");
script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
script_set_attribute(attribute:"solution", value:"Disable IGD or restrict access to trusted networks.");
script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:P");
 script_end_attributes();

 script_summary(english: "Add IGD port mapping");
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

function upnp_svc_url(xml, svc)
{
  local_var	r, s;
  xml = str_replace(string: xml, find: '\r', replace: '');
  xml = str_replace(string: xml, find: '\n', replace: '');
  if ("<serviceType>urn:schemas-upnp-org:service:"+svc+":1</serviceType>" >!< xml) return NULL;
   r = eregmatch(string: xml, pattern: "<controlURL>([^<]+)</controlURL>");
   if (isnull(r)) return NULL;
   return r[1];
}

function find_upnp_service(xml, svc)
{
  local_var	p, i, u;

  while (1)
  {
    p = strstr(xml, '<service>');
    if (isnull(p)) return NULL;
    i = stridx(p, '</service>');
    u = upnp_svc_url(xml: substr(p, 9, i - 1), svc: svc);
    if (u) return u;
    xml = substr(p, i + 9);
  }
}

function make_soap_data(action, svc, fields)
{
  local_var	xml, f;

  xml = strcat('<?xml version="1.0"?>\r\n',
 '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r\n',
 '<SOAP-ENV:Body>\r\n',
 '<m:', action, ' xmlns:m="', svc, '">\r\n');

 foreach f (keys(fields))
 {
   xml = strcat(xml, '<', f, '>', fields[f], '</', f, '>\r\n');
 }
 xml = strcat(xml, '</m:', action, '>\r\n',
'</SOAP-ENV:Body>\r\n',
'</SOAP-ENV:Envelope>\r\n' );
 return xml;
}

function make_soap_req(port, url, action, svc, fields)
{
  local_var	xml, rq;

  xml = make_soap_data(action: action, fields: fields, svc: svc);
  rq = http_mk_post_req(port: port, item: url, data: xml,
     add_headers: make_array('Content-Type', 'text/xml', 
    'SOAPAction', strcat('"', svc, '#', action, '"')) );
  rq['User-Agent'] = NULL;
  rq['Connection'] = NULL;
  rq['Pragma'] = NULL;
  rq['Accept'] = NULL;
  rq['Accept-Language'] = NULL;
  rq['Accept-Charset'] = NULL;
  rq['Cookie'] = NULL;
  rq['Date'] = NULL;
  return rq;
}


port = get_kb_item('upnp/www');
if (! port) exit(0);

gd = get_kb_item('upnp/'+port+'/devdescr');
if (! gd) exit(0);

foreach sv (make_list("WANIPConnection", "WANPPPConnection"))
{
  url = find_upnp_service(xml: gd, svc: sv);
  if (! url) continue;

  testport = rand() % 32768 + 32768;

  fields = make_array(
    'NewRemoteHost', '',
    'NewExternalPort', testport, 
    'NewProtocol', 'TCP',
    'NewInternalPort', testport, 
    'NewInternalClient', this_host(),
    'NewEnabled', 1,
    'NewPortMappingDescription', 'Nessus test '+rand(),
    'NewLeaseDuration', 0 );

  s = 'urn:schemas-upnp-org:service:'+sv+':1';
  act = 'AddPortMapping';
  rq = make_soap_req(port: port, url: url, action: act, fields: fields, svc: s);
  r = http_send_recv_req(port: port, req: rq);

  if (isnull(r)) continue;

  if (r[0] !~ '^HTTP/1\\.[01] 200 ') continue;

  security_warning(port: port);
  set_kb_item(name: 'upnp/igd_add_port_mapping', value: TRUE);

  ## Not necessary
# fields = make_array(
# 'NewRemoteHost', '', 
# 'NewExternalPort', testport, 
# 'NewProtocol', 'TCP');

  act = 'DeletePortMapping';
  rq = make_soap_req(port: port, url: url, action: act, fields: fields, svc: s);
  r = http_send_recv_req(port: port, req: rq);
  break;
}
