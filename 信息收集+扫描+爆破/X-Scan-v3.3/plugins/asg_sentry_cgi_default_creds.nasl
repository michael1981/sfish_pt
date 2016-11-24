#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34395);
  script_version("$Revision: 1.3 $");

  script_name(english:"ASG-Sentry CGI Default Credentials");
  script_summary(english:"Tries to login with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote ASG-Sentry CGI script is configured to use default
credentials to control administrative access.  Knowing these, an
attacker can gain administrative control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("asg_sentry_cgi_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6161);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6161);
if (!get_port_state(port)) exit(0);

user = "admin";
pass = "admin";


# Test an install.
install = get_kb_item(string("www/", port, "/asg_sentry"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = strcat(dir, "/fxm.exe");

  # Get the form data.
  r = http_send_recv3(port: port, method: 'GET', item: url);
  if (isnull(r)) exit(0);

  cookie = "";
  script_name = "";
  caller = "";
  str = strcat('ACTION="', dir, '/fxm.exe?');
  str2 = strcat('ACTION="', dir, '/exs.exe?');
  if (str >< r[2])
  {
    cookie = strstr(r[2], str) - str;
    cookie = cookie - strstr(cookie, '"');
    caller = "/s";
    script_name = "fxm_login.s";
  }
  else if (str2 >< res)
  {
    cookie = strstr(res, str2) - str2;
    cookie = cookie - strstr(cookie, '"');
    caller = "/snmx/";
    script_name = "exs_login.s";
  }

  if (cookie)
  {
    # Try to log in.
    postdata = string(
      "script_name=", script_name, "&",
      "caller=", caller, "&",
      "access=(null)&",
      "username=", user, "&",
      "password=", pass, "&",
      "Login+value=Login"
    );
    r = http_send_recv3(port: port, method: 'POST', 
  item: strcat(url, '?', cookie), version: 11, data: postdata,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

    if (isnull(r)) exit(0);

    # There's a problem if we see the Exit button.
    if ('<!-- Exit Button -->' >< r[2])
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
  else
  {
    debug_print("couldn't find the session cookie!");
  }
}
