#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35580);
  script_version("$Revision: 1.2 $");

  script_name(english:"Profense Web Application Firewall Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"Armorlogic Profense Web Application Firewall is installed on the
remote host.  It is possible to log into the web management interface
using default credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.armorlogic.com/manual/index.htm" );
 script_set_attribute(attribute:"solution", value:
"Please refer to the documentation and follow the steps to change the
default password." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 2000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:2000);
if (!get_port_state(port)) exit(0);

url = "/auth.html?mode=login";

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if ("Profense management login" >< res[2])
{
  res = http_send_recv3(
    method:"POST", 
    item:url, 
    port:port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data:"username=admin&passwd=admin123"
  );
  if (isnull(res)) exit(0);

  if (
    "Set-Cookie:" >< res[1] &&
    'system.html?action=updates' >< res[1]
  )
  {
    if (report_verbosity)
    {
      report = string (
        "\n",
        "Nessus could log into the web management interface using the \n",
        "following credentials :\n",
        "\n",
        "User     : admin",'\n',
        "Password : admin123",'\n',
        "URL      : ",build_url(port:port, qs:url),'\n'
      );
      security_hole(port:port,extra:report);
    }
    else security_hole(port);  
  }
}
