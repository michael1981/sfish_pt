#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38890);
  script_version("$Revision: 1.2 $");

  script_name(english:"VICIDIAL Call Center Suite Default Administrative Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application is protected using default credentials."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running the VICIDIAL Call Center Suite, a set of\n",
      "programs for Asterisk that act as a complete call center suite.\n",
      "\n",
      "The remote installation of VICIDIAL is configured to use default\n",
      "credentials to control administrative access.  Knowing these, an\n",
      "attacker can gain administrative control of the affected application."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Change the password for the admin user."
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


user = "6666";
pass = "1234";


# Loop through directories.
#
# nb: I don't expect the directory will be discovered generally.
dirs = list_uniq(make_list("/vicidial", cgi_dirs()));

foreach dir (dirs)
{
  # Try to exploit the issue to bypass authentication.
  url = string(dir, "/admin.php");

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(
      'Authorization',
      string('Basic ', base64(str:user+":"+pass))
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we've bypassed authentication.
  if (
    'title>VICIDIAL ADMIN:' >< res[2] &&
    '/admin.php?force_logout=1">' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);

      report = string(
        "\n",
        "Nessus was able to verify the vulnerability exists using the following\n",
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
