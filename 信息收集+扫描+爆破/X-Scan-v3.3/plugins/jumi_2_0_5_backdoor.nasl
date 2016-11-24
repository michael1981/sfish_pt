#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42820);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(36883);
  script_xref(name:"OSVDB", value:"59465");

  script_name(english:"Jumi Component for Joomla! <= 2.0.5 Backdoor");
  script_summary(english:"Looks for script created by the backdoor");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that contains a backdoor
allowing execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Joomla on the remote host appears to contain a
backdoor installed as part of a trojaned install of Jumi, a third-
party component used to include custom code into Joomla!.

Using specially crafted input to the 'key' and 'php' parameters of
the 'modules/mod_mainmenu/tmpl/.config.php' script, a remote attacker
can use this backdoor to execute arbitrary code on the remote host, 
subject to the privileges under which the web server operates. 

Note that Jumi versions 2.0.4 and 2.0.5 are known to have been 
trojaned.

Note also that the backdoor has likely sent information about 
Joomla's configuration, including administrative and database 
credentials, to a third-party as part of the component's 
installation."
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/507595/30/0/threaded"
  );
  script_set_attribute(attribute:"see_also", 
    value:"http://code.google.com/p/jumi/issues/detail?id=45"
  );
  script_set_attribute(attribute:"solution", 
    value:
"Remove the affected backdoor script, change credentials used by
Joomla, and investigate whether the affected server has been
compromised."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/10/30"
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


# Check for the backdoor.
url = string(dir, "/modules/mod_mainmenu/tmpl/.config.php");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");


# There's a problem if...
if (
  # we see the response header added by the script and...
  "HTTP/1.0 404 Not Found" >< res[0] &&
  # there's no response body
  isnull(res[2])
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to verify the issue based on the HTTP response header\n",
      "received from the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Joomla install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
