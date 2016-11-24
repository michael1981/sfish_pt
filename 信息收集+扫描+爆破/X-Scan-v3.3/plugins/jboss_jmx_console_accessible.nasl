#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23842);
  script_version("$Revision: 1.9 $");

  script_name(english:"JBoss JMX Console Unrestricted Access");
  script_summary(english:"Tries to access the JMX and Web Consoles");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows unauthenticated access to an
administrative Java servlet." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be a version of JBoss that allows
unauthenticated access to the JMX and/or Web Console servlets used to
manage JBoss and its services.  A remote attacker can leverage this
issue to disclose sensitive information about the affected application
or even take control of it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?997637b6" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b164df" );
 script_set_attribute(attribute:"see_also", value:"http://www.jboss.org/community/wiki/SecureJBoss" );
 script_set_attribute(attribute:"see_also", value:"http://www.jboss.org/community/wiki/SecureTheJmxConsole" );
 script_set_attribute(attribute:"solution", value:
"Secure or remove access to the JMX and/or Web Console
using the advanced installer options." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);	# Also seen on 80 or 8443 (HTTPS)
if (!get_port_state(port)) exit(0);

# Check whether access is allowed.
info = "";

foreach url (make_list("/jmx-console/", "/web-console/"))
{
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  if ("jmx" >< url && 'form action="HtmlAdaptor?action=displayMBeans"' >< r[2])
  {
    set_kb_item(name: "JBoss/jmx-console", value:url);

    info += string(
      "\n",
      "The JMX Console can be accessed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );

    if (!thorough_tests) break;
  }
  else if ("web" >< url && ' src="ServerInfo.jsp"' >< r[2])
  {
    set_kb_item(name: "JBoss/web-console", value:url);

    info += string(
      "\n",
      "The Web Console can be accessed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );

    if (!thorough_tests) break;
  }
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
