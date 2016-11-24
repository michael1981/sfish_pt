#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38952);
  script_version("$Revision: 1.2 $");

  script_name(english:"CrashPlan Server Default Administrative Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application is protected using default credentials."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running CrashPlan or CrashPlan PRO Server, the\n",
      "server component of CrashPlan, a cross-platform backup application.\n",
      "\n",
      "The remote installation of CrashPlan Server is configured to use\n",
      "default credentials to control administrative access.  Knowing these,\n",
      "an attacker can gain administrative control of the affected\n",
      "application."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Change the password for the admin user."
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
  script_require_ports("Services/www", 4280);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:4280, embedded: 0);


user = "admin";
pass = "admin";


# Pull up the login form.
init_cookiejar();

url = "/manage/login.vtl";
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if (
  '<title>CrashPlan' >< res[2] &&
  'action="/manage/login.vtl' >< res[2]
)
{
  # Try to log in.
  cookie = get_http_cookie(name:"jsessionid");
  if (!isnull(cookie)) url2 = string(url, ";jsessionid=", cookie);
  else url2 = url;

  postdata = string(
    "cid=app.loginForm&",
    "onSuccess=/manage/index.vtl&",
    "onFailure=/manage/login.vtl?success=/manage/index.vtl&",
    "onCancel=&",
    "loginForm.email=", user, "&",
    "loginForm.password=", pass, "&"
  );
  res = http_send_recv3(
    port        : port, 
    method      : 'POST', 
    item        : url2, 
    data        : postdata, 
    add_headers : make_array(
      "Content-Type", "application/x-www-form-urlencoded"
    )
  );
  if (isnull(res)) exit(0);

  # There's a problem if we're redirected to the main index.
  if (
    "302 " >< res[0] &&
    egrep(pattern:'^Location: .+/manage/index\\.vtl\\?tid=', string:res[1])
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to gain access using the following information :\n",
        "\n",
        "  URL      : ", build_url(port:port, qs:url), "\n",
        "  Username : ", user, "\n",
        "  Password : ", pass, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
