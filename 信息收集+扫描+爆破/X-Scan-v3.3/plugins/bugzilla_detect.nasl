#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11462);
 script_version ("$Revision: 1.13 $");

 script_name(english:"Bugzilla Software Detection");
 script_summary(english:"Checks for the presence of Bugzilla");

 script_set_attribute(
   attribute:"synopsis",
   value:"A bug tracker is running on the remote host."
 );
 script_set_attribute(
   attribute:"description",
   value:string(
     "The remote web server is hosting Bugzilla, a web application for\n",
     "bug tracking and managing software development."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/"
 );
 script_set_attribute(
   attribute:"solution",
   value:"n/a"
 );
 script_set_attribute(
   attribute:"risk_factor",
   value:"None"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

foreach d (list_uniq(make_list("/bugs", "/bugzilla", cgi_dirs())))
{
  url = string(d, "/query.cgi");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if ( !egrep( pattern:"^HTTP/1.1 200", string:res[ 0 ], icase:FALSE ) )
    continue;

  res = egrep(pattern:"Bugzilla version", string:res, icase:TRUE);
  if( res )
    vers = ereg_replace(pattern:".*Bugzilla version ([0-9.]*).*", string:res, replace:"\1", icase:TRUE);
  else
  {
    url = string(d, "/xmlrpc.cgi");
    xml = string( '<?xml version="1.0" encoding="UTF-8"?><methodCall>',
                  '<methodName>Bugzilla.version</methodName><params /></methodCall>' );
    res = http_send_recv3( method:"POST", item:url, port:port,
                          add_headers: make_array("Content-Type", "text/xml", "Content-Length", "114"),
                          data: xml );
    if (isnull(res)) exit(0);
    if ( !ereg( pattern:"^HTTP/1.1 200", string:res[ 0 ], icase:FALSE ) )
      continue;

    if( "<name>version</name><value><string>" >< res[2] )
      vers = ereg_replace(pattern:".*<name>version</name><value><string>([0-9\.]*)</string>.*",
                          string:res[ 2 ], replace:"\1", icase:FALSE);
  }

  if( vers )
  {
    set_kb_item(name:string("www/", port, "/bugzilla/version"),
            value:vers);

    rep = string(
      "Nessus detected the following installation of Bugzilla :\n\n",
      "  Directory : ", d, "\n",
      "  Version   : ", vers, "\n"
    );
    security_note(port:port, extra:rep);
    exit(0);
  }
}
