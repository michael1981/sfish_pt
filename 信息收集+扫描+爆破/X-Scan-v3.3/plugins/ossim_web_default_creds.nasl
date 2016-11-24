#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42337);
  script_version("$Revision: 1.1 $");

  script_name(english:"OSSIM Web Frontend Default Credentials");
  script_summary(english:"Tries to login as admin/admin");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application uses default credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "It is possible to log into the remote OSSIM web frontend by providing\n",
      "the default credentials.  A remote attacker could exploit this to\n",
      "gain administrative control of the OSSIM web frontend."
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:"Secure the admin account with a strong password."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/02"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'ossim', port:port);
if (isnull(install)) exit(1, "OSSIM wasn't detected on port "+port+".");

user = 'admin';
pass = 'admin';
url = string(install['dir'], '/session/login.php');
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

headers = make_array("Content-Type", "application/x-www-form-urlencoded"); 
postdata = string("user=", user, "&", "pass=", pass);
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  add_headers:headers,
  data:postdata
);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
  
hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# If the login succeeds, we'll be redirected to the admin console
if (
  code == 302 &&
  "../index.php" >< location
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to gain access using the following information :\n",
      "\n",
      "URL      : ",build_url(port:port, qs:url), "\n",
      "User     : ",user,'\n',
      "Password : ",pass,'\n'
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The OSSIM install at "+build_url(port:port, qs:url)+" is not affected.");

