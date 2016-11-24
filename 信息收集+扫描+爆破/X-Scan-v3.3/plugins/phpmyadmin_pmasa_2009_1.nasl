#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36083);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(34253);
  script_xref(name:"Secunia", value:"34468");
  script_xref(name:"OSVDB", value:"53226");
  script_xref(name:"OSVDB", value:"53227");

  script_name(english:"phpMyAdmin file_path Parameter Vulnerabilities (PMASA-2009-1)");
  script_summary(english:"Calls bs_disp_as_mime_type.php with a bogus URL");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is affected by\n",
      "multiple issues."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of phpMyAdmin installed on the remote host fails to\n",
      "sanitize user-supplied input to the 'file_path' parameter of the\n",
      "'bs_disp_as_mime_type.php' script before using it to read a file and\n",
      "reporting it in dynamically generated HTML.  An unauthenticated remote\n",
      "attacker may be able to leverage this issue to read arbitrary files,\n",
      "possibly from third-party hosts, or to inject arbitrary HTTP headers\n",
      "in responses sent to third-party users.\n",
      "\n",
      "Note that the application is also reportedly affected by several other\n",
      "issues, although Nessus has not actually checked for them."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-1.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to phpMyAdmin 3.1.3.1 or apply the patch referenced in the\n",
      "project's advisory."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  basename = SCRIPT_NAME;
  exploit_url = build_url(port:port, qs:dir+"/"+basename);

  url = string(
    dir, "/bs_disp_as_mime_type.php?",
    "file_path=", exploit_url, "&",
    "c_type=1"
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # we see a header line with our file or ...
    string("attachment; filename=", basename) >< res[1] ||
    # we see an error indicating get_headers() failed (eg, connection failed).
    string("get_headers(", exploit_url, ")") >< res[2]
  )
  {
    security_warning(port);
  }
}
