# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# upnp_func.inc 
# $Revision: 1.1 $
#

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

function upnp_find_service(xml, svc)
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

function upnp_make_soap_data(action, svc, fields)
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

function upnp_make_soap_req(port, url, action, svc, fields)
{
  local_var	xml, rq;

  xml = upnp_make_soap_data(action: action, fields: fields, svc: svc);
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


# Local Variables: **
# mode:Fundamental **
# comment-column:0 **
# comment-start: "# "  **
# End: **
