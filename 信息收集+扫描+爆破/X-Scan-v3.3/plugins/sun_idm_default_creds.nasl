#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35105);
  script_version("$Revision: 1.2 $");

  script_name(english:"Sun Java System Identity Manager Default Credentials");
  script_summary(english:"Tries to login with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote installation of Sun Java System Identity Manager is
configured to use default credentials to control administrative
access.  Knowing these, an attacker can gain administrative control of
the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'Configurator' user." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("sun_idm_detect.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


user = "Configurator";
pass = "configurator";


# Test an install.
install = get_kb_item(string("www/", port, "/sun_idm"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Pull up the login form.
  url = string(dir, "/login.jsp?lang=en&cntry=");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (
    'title>Identity Manager<' >< res[2] &&
    'action="login.jsp;jsessionid=' >< res[2]
  )
  {
    # Try to log in.
    postdata = string(
      "id=&",
      "command=login&",
      "activeControl=&",
      "accountId=", user, "&",
      "password=", pass, "&"
    );
    res = http_send_recv3(
      method:'POST', 
      item:url, 
      data:postdata, 
      port:port, 
      version:11, 
      add_headers:make_array(
        "Content-Type", "application/x-www-form-urlencoded"
      )
    );
    if (isnull(res)) exit(0);

    # There's a problem if we're redirected to the home page.
    if (
      "302 " >< res[0] &&
      egrep(pattern:'^Location: .+/home/index\\.jsp', string:res[1])
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to gain access using the following credentials :\n",
          "\n",
          "  User     : ", user, "\n",
          "  Password : ", pass, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}
