#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40988);
  script_version("$Revision: 1.4 $");

  script_xref(name:"milw0rm", value:"9601");
  script_xref(name:"OSVDB", value:"57883");
  script_xref(name:"Secunia", value:"36657");

  script_name(english:"BF Survey Pro Component for Joomla! table Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is susceptible to\n",
      "a SQL injection attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running BF Survey Pro or BF Survey Pro Free, a\n",
      "third-party component for Joomla! for conducting surveys.\n",
      "\n",
      "The version of this component installed on the remote host fails to\n",
      "sanitize input to the 'table' parameter in a POST request (when 'task'\n",
      "is set to 'updateOnePage') before using it in a database query.\n",
      "\n",
      "An unauthenticated remote attacker can leverage this issue to\n",
      "manipulate SQL queries and, for example, reset the administrator's\n",
      "password and gain administrative access to the affected application."
    )
  );
  # Information received from the author on 2009-09-17
  script_set_attribute(attribute:"solution", 
    value:"Update to BF Survey Pro 1.2.6.");
  script_set_attribute(attribute:"see_also", 
    value: "http://www.tamlyncreative.com.au/software/forum/index.php?topic=357.0");

  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/15"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(1, "The 'www/"+port+"/joomla' KB item is missing.");
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1, "The 'www/"+port+"/joomla' KB item ("+install+") is invalid.");

dir = matches[2];

# Check possible affected components.
components = make_list(
  "com_bfsurvey_profree",
  "com_bfsurvey_pro"
);

foreach component (components)
{
  # Make sure the component is installed.
  url = string(dir, "/index.php?option=", component);

  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  if (
    string("/components/", component, "/css/style.css") >< res[2] ||
    string("option=", component, "&amp;view=openpage") >< res[2]
  )
  {
    exploit = string(SCRIPT_NAME, " SET NESSUS=", unixtime(), " -- ");
    postdata = string(
      "task=updateOnePage&",
      "table=", urlencode(str:exploit)
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

    # There's a problem if we see a SQL syntax error.
    if (string("SQL=INSERT INTO ", exploit, "( `id`") >< res[2])
    {
      set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

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
}
