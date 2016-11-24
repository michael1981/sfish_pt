#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35712);
 script_version("$Revision: 1.5 $");
 script_name(english: "Web Server UPnP Detection");

 script_set_attribute(attribute:"synopsis", value:"The remote web server provides UPnP information.");
 script_set_attribute(attribute:"description", value:
"It was possible to extract some information about the UPnP-enabled
device by querying this web server.
Services may also be reachable through SOAP requests.");
 script_set_attribute(attribute:"see_also", value: 
"http://en.wikipedia.org/wiki/Universal_Plug_and_Play");
 script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port if desired.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();

 script_summary(english: "Grabs UPnP XML description file");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("http_version.nasl", "upnp_search.nasl");
# script_require_keys("upnp/location");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('upnp_func.inc');

function get_devdescr(port, item, host)
{
  local_var	h, lines, l, r;

  r = http_send_recv3(port: port, item: item, method: "GET", host: host);
  if (isnull(r)) return NULL;
  if ( r[0] =~ '^HTTP/1\\.[01] 200 ' && '<?xml version="1.0"?>' >< r[2])
    return r[2];
  return NULL;
}

fields = make_list("deviceType", "friendlyName", "manufacturer", "manufacturerURL", "modelName", "modelDescription", "modelName", "modelNumber", "modelURL", "serialNumber");

function parse_devdescr(xml)
{
  local_var	line, f, cnt, r, rep;

  if (isnull(xml)) return NULL;

  cnt = 0;
  rep = '';
  foreach line (split(xml, keep: 0))
  {
    if ('<device>' >< line) cnt ++;
    if (cnt > 1 && strlen(rep) > 0) return rep;
    foreach f (fields)
    {
      r = eregmatch(string: line, pattern: strcat('^[ \t]*<', f, '>([^<]+)'));
      if (! isnull(r))
      {
        rep = strcat(rep, f, ':', r[1], '\n');
	break;
      }
    }
  }
  return rep;
}

function report(url, info, port)
{
  local_var	e;
  
  if (strlen(info))
    e = strcat('\nHere is a summary of ', url, ' :\n\n', info);
  else
    e = strcat('\nBrowse ', url, ' for more information\n');
  security_note(port: port, extra: e);
  if (COMMAND_LINE) display(e);
}

####

url = get_kb_item('upnp/location');
if (url)
{
  h = split_url(url: url);
  if (! isnull(h))
  {
    port = int(h["port"]);
    if ( get_port_state(port) && 
       	 (! h["ssl"] || get_port_transport(port) <= ENCAPS_IP) )
    {
      gd = get_devdescr(port: port, item: h["page"], host: h["host"]);
      if (! isnull(gd)) 
      {
        set_kb_item(name: 'upnp/www', value: port);
	r = parse_devdescr(xml: gd);
	if (! isnull(r))
	{
	  set_kb_item(name: 'upnp/'+port+'/devdescr', value: gd);
	  report(url: url, info: r, port: port);
	  if (! thorough_tests) exit(0);
	}
      }
    }
  }
}

port = get_http_port(default: 49152, embedded: 1);

foreach p (make_list("/gatedesc.xml", "/devdescr.xml", "/dyndev/uuid:0000e018-d0a0-00e0-d0a0-484800e808e0", "/", "/wanipconn-361.xml"))
{
  gd = get_devdescr(port: port, item: p);
  if (isnull(gd)) continue;
  r = parse_devdescr(xml: gd);
  if (strlen(r) > 0)
  {
    u = build_url(port: port, qs: p);
    set_kb_item(name: 'upnp/location', value: u);
    set_kb_item(name: 'upnp/www', value: port);
    set_kb_item(name: 'upnp/'+port+'/devdescr', value: gd);
    report(url: u, info: r, port: port);
    exit(0);
  }
}
