#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36019);
  script_version("$Revision: 1.2 $");

  script_name(english:"Tenable Security Center Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application can be accessed with default credentials." );
  script_set_attribute(attribute:"description", value:
"Tenable Network Security's Security Center, an asset-based security 
and compliance monitoring application, is installed on the remote 
system. By supplying default credentials, it is possible to log into 
the remote web application." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/products/sc/" );
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation and follow the steps to change the default
password." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

url = "/sc3/console.php?psid=101";

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if ("Tenable Network Security's Security Center" >< res[2])
{
  # Get the cookies and try to log in.

  cookie = get_http_cookie(name:"TNS_SESSIONID");
  if (!cookie) exit(0);
  cookie = string("TNS_SESSIONID=",cookie);

  vcookie = get_http_cookie(name:"TNS_VERIFYID");
  if (!vcookie) exit(0);
  vcookie = string("TNS_VERIFYID=",vcookie);

  username = "admin";
  password = "admin";

  creds = string("psid=102&ctxid=default&auth2_username=",username,"&auth2_password=",base64(str:password));  

  res = http_send_recv3(
         method:"POST", 
         item:"/sc3/console.php?", 
         port:port,
         add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
         "Cookie",string(vcookie,";",cookie),
         "Content-Length",strlen(creds)),
         data:creds
       );

  if (isnull(res)) exit(0);

  if("/sc3/console.php" >< res[1])
  {
    res = http_send_recv3(method:"GET", item:"/sc3/console.php?psid=9209", 
           port:port,
           add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
           "Cookie",string(vcookie,";",cookie)));
    if (isnull(res)) exit(0);

    if ("Configure the Security Center" >< res[2] &&
        ">View Admin & Customer Activity Log<" >< res[2])
    {
      if(report_verbosity > 0)
      {  
        report = string ('\n',
          "Nessus could log into the web application using the following \n",
          "credentials :",'\n',
          "\n",
          "User     : ",username,'\n',
          "Password : ",password,'\n',
          "URL      : ",build_url(port:port, qs:url),'\n');

        security_hole(port:port,extra:report);
      }
      else
       security_hole(port);
    }
  }
}
