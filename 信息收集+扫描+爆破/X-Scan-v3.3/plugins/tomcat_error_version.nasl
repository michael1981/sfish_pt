#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39446);
  script_version("$Revision: 1.2 $");

  script_name(english:"Apache Tomcat Default Error Page Version Detection");
  script_summary(english:"Tries to get a Tomcat version number from a 404 page");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server reports its version number on error pages."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "Apache Tomcat appears to be running on the remote host and reporting\n",
      "its version number on the default error pages.  A remote attacker\n",
      "could use this information to mount further attacks."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wiki.apache.org/tomcat/FAQ/Miscellaneous#Q6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://jcp.org/en/jsr/detail?id=315"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Replace the default error pages with custom error pages to hide\n",
      "the version number.  Refer to the Apache wiki or the Java Servlet\n",
      "Specification for more information."
    )
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Unless we're paranoid, make sure the banner looks like Tomcat.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);

  if (
    !banner ||
    (
      "Server: Apache-Coyote" >!< banner &&
       "Server: Apache Tomcat" >!< banner &&
       "Server: Tomcat Web Server" >!< banner
    )
  ) exit(1, "The HTTP banner does not look like Apache Tomcat");
}

# Request a page that will likely return a 404, and see if it includes
# a version number
url = string("/nessus-check/", SCRIPT_NAME);
res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE);
if (isnull(res)) exit(1, "Error requesting 404 page");

if (res[0] =~ '^HTTP/1\\.[01] +404 ')
{
  pattern = '<title>Apache Tomcat/([0-9.]+) - Error report</title>';
  match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
  if (isnull(match)) exit(1, "Tomcat version not found in <title> of 404 page");

  version = match[1];
  set_kb_item(name:"tomcat/" + port + "/error_version", value:version);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus detected the following version number on an Apache Tomcat\n",
      "404 page :\n\n",
      "  ", version, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
