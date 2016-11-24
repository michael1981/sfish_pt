#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34474);
 script_version("$Revision: 1.8 $");

 script_name(english: "Broken Web Server Detection");
 script_set_attribute(attribute:"synopsis", value:
"Tests on this web server have been disabled." );
 script_set_attribute(attribute:"description", value:
"The remote web server seems password protected or misconfigured.  

Further tests on it will be disabled so that the whole scan is not 
slowed down." );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value: "N/A");
script_end_attributes();

 script_summary(english: "Checks that the web server is working correctly and quickly");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("httpver.nasl");
 script_require_ports("Services/www");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function declare_broken(port, reason)
{
  debug_print('declare_broken: port=', port, ' reason=', reason);
  set_kb_item(name: "Services/www/" +port+ "/broken", value: TRUE);
  set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
  if (isnull(reason))
    set_kb_item(name: "Services/www/" +port+ "/broken/reason", value: "unknown");
  else
    set_kb_item(name: "Services/www/" +port+ "/broken/reason", value: reason);
  exit(0);
}

timeout = get_read_timeout();

port = get_kb_item("Services/www");
# Do not add default ports here. This script must only run on identified
# web servers.

if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/"+port+"/broken") ||
     get_kb_item("Services/www/"+port+"/working") ) exit(0);

starttime = unixtime();
r = http_send_recv3(port: port, method: 'GET', item: '/', version: 11, no_body: 1);

if (isnull(r))
{
  soc = open_sock_tcp(port);
  if (soc)
  {
   close(soc);
   declare_broken(port: port);
  }
  else
   declare_broken(port: port, reason: strcat('TCP port ', port, ' appears closed or filtered now\n'));
}

endtime = unixtime();

delay = endtime - starttime;
if (delay > 2 * timeout)
 declare_broken( port: port, 
 		 reason: 'It took '+delay+' seconds to read /\n');

if (r[0] =~ '^HTTP/[0-9.]+ 503 ')
  declare_broken(port: port, 
   reason: 'The server answered with a 503 code (overloaded).\n');

if (r[0] =~ '^HTTP/[0-9.]+ +403 ' && delay >= timeout)
  declare_broken(port: port, 
   reason: 'The server took '+delay+' seconds to send back a 403 code on /\n');

if ("HTTP" >!< r[0])
  declare_broken(port: port, 
   reason: 'The server appears to speak HTTP/0.9 only\n');

if (port == 5000 && r[0] =~ "^HTTP/[0-9.]+ +400 ")
  declare_broken(port: port);

if (port == 2381 && r[0] =~ "^HTTP/1\.0 ")
  declare_broken(port: port);

set_kb_item(name: "Services/www/" +port+ "/working", value: TRUE);
