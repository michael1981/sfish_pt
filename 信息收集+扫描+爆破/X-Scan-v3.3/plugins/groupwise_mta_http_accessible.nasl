#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35725);
  script_version("$Revision: 1.2 $");

  script_name(english:"Novell GroupWise MTA Web Console Accessible");
  script_summary(english:"Tries to access the MTA Web Console");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server allows unauthenticated access to administrative\n",
      "tools."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote web server is a Novell GroupWise MTA Web Console, used to\n",
      "monitor and potentially control a GroupWise MTA via a web browser.\n",
      "\n",
      "By allowing unauthenticated access, anyone may be able to do things\n",
      "such as discover the version of GroupWise installed on the remote and\n",
      "its configuration, track GroupWise message traffic, or change the\n",
      "MTA's configuration settings."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw6/gw6_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw65/gw65_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw7/gw7_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw8/gw8_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Consult the GroupWise Administration Guide for information about\n",
      "restricting access to the MTA Web Console."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7180);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:7180);
if (!get_port_state(port)) exit(0);


# Call up the default URL.
url = "/";
res = http_get_cache(item:url, port:port);
if (isnull(res)) exit(0);


# There's a problem if we were able to access the console.
if ("<HEAD><TITLE>GroupWise MTA -" >< res)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to access the remote GroupWise install's MTA Web\n",
      "Console using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
