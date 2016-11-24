#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39501);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-2254", "CVE-2009-2255");
  script_bugtraq_id(35467, 35468);
  script_xref(name:"milw0rm", value:"9004");
  script_xref(name:"milw0rm", value:"9005");
  script_xref(name:"OSVDB", value:"55343");
  script_xref(name:"OSVDB", value:"55344");

  script_name(english:"Zen Cart password_forgotten.php Admin Access Bypass");
  script_summary(english:"Tries to access the application's version info");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is susceptible \n",
      "to an authentication bypass."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Zen Cart installed on the remote host is affected by a\n",
      "design error that allows a remote attacker to bypass authentication\n",
      "and gain access to the application's admin section by appending\n",
      "'/password_forgotten.php' to URLs.  Successful exploitation of this\n",
      "vulnerability may lead to disclosure of sensitive information such as\n",
      "customer data, SQL injection attacks, or arbitrary code execution."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zen-cart.com/forum/showthread.php?t=130161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Apply the patch referenced in the project's advisory above."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to pull up version info page in the admin control panel.
  url = string(
    dir, "/admin/server_info.php",
    "/password_forgotten.php"
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # If we see the expected contents...
  if (
    'admin/configuration.phyp?gID=' >< res[2] ||
    'TITLE_SERVER_HOST' >< res[2]
  )
  {
    # Unless we're paranoid, make sure we don't normally have access.
    if (report_paranoia < 2)
    {
      url2 = url - "/password_forgotten.php";
      res2 = http_send_recv3(method:"GET", item:url2, port:port);
      if (isnull(res2)) exit(0);

      if (
        'admin/configuration.phyp?gID=' >< res2[2] ||
        'TITLE_SERVER_HOST' >< res2[2]
      ) exit(0);
    }

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following URL :\n",
        "\n",
        " ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
