#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11801);
  script_version ("$Revision: 1.12 $");
 
  script_name(english:"HTTP Method Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the web server." );
 script_set_attribute(attribute:"description", value:
"The remote web server seems to be vulnerable to a format string attack
on the method name.
An attacker might use this flaw to make it crash or even execute 
arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or contact your vendor and inform him of this 
vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Sends an HTTP request with %s as a method");
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

u = strcat("/nessus", rand_str(), ".html");
w = http_send_recv3(method:"GET", item: u, port: port);
r = strcat(w[0], w[1], '\rn', w[2]);

flag = 0; flag2 = 0;
if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
{
  flag = 1;
  debug_print('Normal answer:\n', r);
}

soc = http_open_socket(port);
if (! soc) exit(0);

foreach bad (make_list("%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x"))
{
  w = http_send_recv3(method: bad, item: u, port: port);
  if (isnull(w)) break;
  r = strcat(w[0], w[1], '\r\n', w[2]);
  if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
  {
    debug_print('Format string:\n', r);
    flag2 ++;
  }
}

if (http_is_dead(port: port))
{
  security_hole(port);
  exit(0);
}
