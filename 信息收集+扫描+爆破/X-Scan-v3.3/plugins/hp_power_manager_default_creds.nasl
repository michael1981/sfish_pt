#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42832);
  script_version("$Revision: 1.1 $");

  script_name(english:"HP Power Manager Default Credentials");
  script_summary(english:"Attempts to log in with default credentials.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is hosting a web application that uses default
login credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HP Power Manager, a web based user
definable UPS management and monitoring utility.  The installed
version has a default password ('admin') set.  An attacker may connect
to it to reconfigure the application and control remote UPSs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?386aa1fb"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Set a strong password for the 'admin' account."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/17"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("hp_power_mgr_web_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:'hp_power_mgr', port:port);
if (isnull(install)) exit(1, "HP Power Manager wasn't detected on port "+port+".");
dir = install['dir'];

login='admin';
pass='admin';

url = string(dir, '/goform/formLogin?Login=', login, '&Password=', pass);
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ("top.location.href = '/Contents/index.asp';" >< res[2])
{
  #Be sure this is HP Power Manager by following /Contents.index.asp
  #This doesn't work with follow_redirect because the original request
  #return HTTP/1.0  200 rather than 3xx
  res2 = http_send_recv3(method:"GET", item:"/Contents/index.asp", port:port);
  if (isnull(res2)) exit(1, "The web server on port "+port+" failed to respond.");

  if (
    "<title>HP Power Manager</title>" >< res2[2] &&
    "<frame name=head src=topFrame.html scrolling=no noresize>" >< res2[2] &&
    '<frame name="main" src="UPS/blank.asp" scrolling="auto" noresize>' >< res2[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = get_vuln_report(items:url, port:port);
      security_hole(port:port, extra:report);
    }
    else security_hole(port:port);
  }
}
else exit(0, "The HP Power Manager install at "+build_url(port:port, qs:dir+"/index.asp")+" is not affected.");

