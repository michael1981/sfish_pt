#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35803);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-0807");
  script_xref(name:"milw0rm", value:"8092");
  script_xref(name:"OSVDB", value:"48866");

  script_name(english:"zFeeder admin.php Direct Request Admin Authentication Bypass");
  script_summary(english:"Tries to access configruation settings");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server allows unauthenticated access to its admin\n",
      "panel."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running zFeeder, an open source PHP application\n",
      "used to aggregate RSS content.\n",
      "\n",
      "The remote installation of zFeeder is configured by default using\n",
      "empty values for the admin's username and password.  A remote attacker\n",
      "can leverage this issue to gain administrative control of the affected\n",
      "application."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Access the application's admin panel and change the admin username and\n",
      "password."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/newsfeeds", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # See if admin.php exists and allows uncredentialed configuration access.
  url = string(dir, "/admin.php?zfaction=config");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res))exit(0);

  if ("username :</font>" >< res[2])
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to access the admin panel with empty credentials\n",
        "using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
