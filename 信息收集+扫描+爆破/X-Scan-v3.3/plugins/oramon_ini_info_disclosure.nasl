#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35008);
  script_version("$Revision: 1.2 $");

  script_xref(name:"milw0rm", value:"7286");

  script_name(english:"OraMon config/oramon.ini Information Disclosure");
  script_summary(english:"Tries to read oramon.ini");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OraMon, an Oracle database monitoring tool
written in PHP. 

The OraMon installation on the remote host stores its configuration
file in the web document directory and fails to restrict access to it. 
An unauthenticated attacker can retrieve it and discover sensitive
information, such as credentials used for connecting to an Oracle
database." );
 script_set_attribute(attribute:"solution", value:
"Use a .htaccess file or an equivalent to control access to files in
the application's 'config' directory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/oramon", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve the file.
  url = string(dir, "/config/oramon.ini");

  req = http_mk_get_req(port:port, item:url);
  res = http_send_recv_req(port:port, req:req);
  if (res == NULL) exit(0);

  # If we see the expected contents...
  if (
    '$USERID' >< res[2] && 
    '$PASSWORD' >< res[2] &&
    '$DATABASE' >< res[2]
  )
  {
    if (report_verbosity)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to exploit the issue to retrieve the contents of\n",
        "OraMon's configuration file using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        report += string(
          "\n",
          "Here are the contents :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:res[2]), "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
