#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34947);
  script_version("$Revision: 1.3 $");

  script_name(english:"Apache Struts devMode Information Disclosure");
  script_summary(english:"Checks for Struts debug xml output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java framework that is configured to
operate in debug mode." );
 script_set_attribute(attribute:"description", value:
"The remote web server is using Apache Struts, a web application
framework for developing Java EE web applications. 

The version of Apache Struts installed on the remote host is
configured to operate in development mode (devMode).  While this
environment can help speed up development of web applications, it can
leak information about the underlying web applications as well as the
installation of Struts, Java, and others related items on the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/2.0.12/docs/devmode.html" );
 script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/2.0.12/docs/debugging.html" );
 script_set_attribute(attribute:"solution", value:
"If this server is used in a production environment, disable
development mode." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


action = string("Nessus-", unixtime());
max_debug_bytes = 8192;


# Iterate over known directories.
dirs = get_kb_list(string("www/", port, "/content/directories"));
if (isnull(dirs)) dirs = make_list("", "/struts2-showcase", "/struts-showcase");

foreach dir (dirs)
{
  # Identify a web app using Struts.
  res = http_send_recv3(
    port   : port, 
    method : "GET",
    item   : string(dir, "/struts/webconsole.html")
  );
  if (res == NULL) exit(0);

  # If so...
  if (
    "Apache Software Foundation (ASF)" >< res[2] &&
    ">OGNL Console<" >< res[2]
  )
  {
    # Try to get XML debugging output for an invalid action.
    url = string(dir, "/", action, ".action?debug=xml");
    res = http_send_recv3(
      port   : port, 
      method : "GET",
      item   : url
    );
    if (res == NULL) exit(0);

    # There's a problem if we get debug output.
    if (
      "<title>Struts Problem Report" >< res[2] &&
      "<debug>" >< res[2]
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve information about\n",
          "framework-specific objects at runtime on the remote host using the\n",
          "following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          output = strstr(res[2], "<debug>");
          if ("</debug>" >< output) output = output - strstr(output, "</debug>");
          if (strlen(output) > max_debug_bytes)
          {
            output = substr(output, 0, max_debug_bytes-1);
            truncated = TRUE;
          }
          else truncated = FALSE;

          report += string(
            "\n",
            "Here are the results :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
          );
          if (truncated)
          {
            report += string(
              "\n",
              "Note that only the first ", max_debug_bytes, " bytes of debugging output\n",
              "have been included in the report.\n"
            );
          }
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
