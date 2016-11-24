#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40349);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2353");
  script_bugtraq_id(35917);

  script_name(english:"eAccelerator encoder.php File Backup");
  script_summary(english:"Tries to copy files to an invalid directory");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that can allows\n",
      "execution of arbitrary code remotely."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server appears to be using eAccelerator, an open source\n",
      "extension for PHP designed to accelerate, optimize, and cache PHP\n",
      "scripts.\n",
      "\n",
      "The script 'encoder.php' included with the installation of\n",
      "eAccelerator on the remote host fails to sanitize user-supplied input\n",
      "to the 'source' and 'target' parameters before using it to copy files\n",
      "from one location (possibly even a third-party site accessible via FTP\n",
      "or SMB) to another.  An unauthenticated remote attacker may be able to\n",
      "leverage this issue to disclose sensitive information, overwrite\n",
      "important files, or even execute arbitrary code, all subject to the\n",
      "privileges of the web server user id."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/504695/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/02"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/22"
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
if (thorough_tests) dirs = list_uniq(make_list("/eaccelerator", "/eAccelerator", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/encoder.php");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server did not respond.");

  # If so ...
  if (
    '<title>eAccelerator Encoder</title>' >< res[2] &&
    'input type="text" name="source"' >< res[2] &&
    'input type="text" name="target"' >< res[2]
  )
  {
    # Try to generate an error message involving the target directory.
    #
    # nb: this won't actually create the directory because the script
    #     calls PHP's mkdir() function without the recursion flag.
    source = ".";
    target = string("NESSUS/", SCRIPT_NAME, "/", unixtime());

    postdata = string(
      "source=", source, "&",
      "target=", target, "&",
      "suffixies=php&",
      "submit=OK"
    );

    req = http_mk_post_req(
      port        : port,
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      )
    );
    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(1, "The web server did not respond.");

    # There's a problem if we couldn't create the target directory.
    if (string("ERROR: Can't create destination directory ", '"', target, '"') >< res[2])
    {
      if (report_verbosity > 0)
      {
        req_str = http_mk_buffer_from_req(req:req);

        report = string(
          "\n",
          "Nessus was able to verify the issue exists using the following\n",
          "request :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
exit(0, "The host is not affected.");
