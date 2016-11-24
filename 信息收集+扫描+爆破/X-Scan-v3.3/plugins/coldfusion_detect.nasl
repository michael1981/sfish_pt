#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42339);
  script_version("$Revision: 1.1 $");

  script_name(english:"Adobe ColdFusion Detection");
  script_summary(english:"Looks for the ColdFusion admin login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application platform was detected on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "Adobe ColdFusion, a rapid application development platform, is\n",
      "running on the remote web server."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/products/coldfusion/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

# The installer always puts ColdFusion in the same location
dir = '/CFIDE';
item = '/administrator/index.cfm';
url = string(dir, item);

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if ('<title>ColdFusion Administrator Login</title>' >< res[2])
{
  installs = add_install(
    installs:installs,
    dir:dir,
    appname:'coldfusion',
    port:port
  ); 

  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:'ColdFusion',
      installs:installs,
      item:item,
      port:port
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "ColdFusion wasn't detected on port "+port+".");
