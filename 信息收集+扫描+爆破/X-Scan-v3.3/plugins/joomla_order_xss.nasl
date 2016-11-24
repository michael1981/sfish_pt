#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25823);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-4189");
  script_bugtraq_id(25122);
  script_xref(name:"OSVDB", value:"38756");

  script_name(english:"Joomla! com_content Component (components/com_content/content.php) order Parameter XSS");
  script_summary(english:"Tries to exploit an XSS issue in com_content");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla installed on the remote host fails to sanitize
user-supplied input to the 'order' parameter before using it in the
'components/com_content/content.php' script to generate dynamic
output.  An unauthenticated remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site. 

In addition, the application may also be affected by a session
fixation vulnerability in the administrator application as well as
several other cross-site scripting and cross-site request forgery
vulnerabilities, although Nessus did not test for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dadacc25" );
 script_set_attribute(attribute:"see_also", value:"http://forum.joomla.org/index.php?topic=195272.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla 1.0.13 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "cross_site_scripting.nasl");
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
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue.
  xss = string("nessus", "\", "'", '\\"', " onclick=alert(1); ", 'nessus=\\"');
  exss = urlencode(
    str:xss,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;\\"
  );

  if (thorough_tests) cats = make_list(1, 3, 7);
  else cats = make_list(1);
  foreach cat (cats)
  {
    req = http_get(
      item:string(
        dir, "/index.php?",
        "option=com_content&",
        "task=category&",
        "sectionid=-1&",
        "id=", cat, "&",
        "Itemid=-9&",
        "order=", exss, "&",
        "limit=10&",
        "limitstart=0"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we see our exploit.
    #
    # nb: account for Joomla's escaping of our exploit.
    xss2 = str_replace(find:"\", replace:"\\\", string:xss);
    if (
      # nb: not search-engine optimized
      string("order=", xss2, "&amp;limit=' + this.options[selectedIndex]") >< res ||
      # nb: search-engine optimized
      string("order,", xss2, "/' + this.options[selectedIndex]") >< res
    )
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
