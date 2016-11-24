#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35649);
  script_version("$Revision: 1.3 $");

  script_name(english:"Trend Micro InterScan Web Security Suite Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"Trend Micro InterScan Web Security Suite is installed on the remote
host.  It is possible to log into the web management interface using
default credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc4cc287" );
 script_set_attribute(attribute:"solution", value:
"Refer to the documentation for instructions about changing the default
password." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl","iwss_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 1812);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1812,embedded:TRUE);
if (!get_port_state(port)) exit(0);
if (!get_kb_item(string("Services/www/",port,"/iwss"))) exit(0);

# Send a login POST request.
url = "/logon.jsp";
login = "admin";
password = "adminIWSS85";

res = http_send_recv3(
  method:"POST", 
  item:"/uilogonsubmit.jsp", 
  port:port,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
  data:string("wherefrom=summary_scan&uid=",login,"&passwd=",password)
);
if (isnull(res)) exit(0);

if ('summary_scan' >< res[1])
{
  # Double check by sending a request to a page that definitely
  # requires credentials.

  res = http_send_recv3(method:"GET", item:"/index.jsp?summary_scan", port:port);
  if ("system_dashboard.jsp" >< res[2])
  {
    if(report_verbosity)
    {
      report = string (
        "\n",
        "Nessus could log into the web management interface using the \n",
        "following  credentials :\n",
        "\n", 
        "User     : ",login,'\n',
        "Password : ",password,'\n',
        "URL      : ", build_url(port:port, qs:url)
      );
      security_hole(port:port,extra:report);  
    }
    else security_hole(port);  
  }
}
