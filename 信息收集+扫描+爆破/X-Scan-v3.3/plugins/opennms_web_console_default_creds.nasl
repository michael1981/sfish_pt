#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34351);
  script_version("$Revision: 1.4 $");

  script_name(english:"OpenNMS Web Console Default Credentials");
  script_summary(english:"Tries to login to the web console with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote OpenNMS Web Console is configured to use default
credentials to control administrative access.  Knowing these, an
attacker can gain administrative control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("opennms_web_console_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8980);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8980);

user = "admin";
pass = "admin";


# Test an install.
install = get_kb_item(string("www/", port, "/opennms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  init_cookiejar();
  # Get a session cookie.
  r = http_send_recv3(method: "GET", item:string(dir, "/acegilogin.jsp"), port:port);
  if (isnull(r)) exit(0);

  cookie = "";
  if ('<form action="j_acegi_security_check;jsessionid=' >< r[2])
  {
    cookie = strstr(r[2], '<form action="j_acegi_security_check;jsessionid=') -
             '<form action="j_acegi_security_check;jsessionid=';
    cookie = cookie - strstr(cookie, '"');
  }

  if (cookie)
  {
    # Try to log in.
    postdata = string(
      "j_username=", user, "&",
      "j_password=", pass, "&",
      "Login=Login"
    );
    set_http_cookie(name: "JSESSIONID", value: cookie);
    r = http_send_recv3(method: "POST", item: strcat(dir, "/j_acegi_security_check"), port: port,
      version: 11, data: postdata,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # If we didn't see a failure message...
    if ('/acegilogin.jsp?login_error=1' >!< r[2])
    {
      # Make sure we really can get in.
      r = http_send_recv3(method: "GET", item:string(dir, "/index.jsp"), port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we can.
      if (
        '<a href="j_acegi_logout">' >< r[2] &&
        '<a href="dashboard.jsp">' >< r[2]
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
  else
  {
    debug_print("couldn't find the session cookie!\n");
  }
}
