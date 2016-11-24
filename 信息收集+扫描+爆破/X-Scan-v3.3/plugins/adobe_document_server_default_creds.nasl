#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21099);
  script_version("$Revision: 1.7 $");

  script_name(english:"Adobe Document Server Default Credentials");
  script_summary(english:"Checks for default credentials in Adobe Document Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The administration console for the remote web server is protected with
default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The installation of Adobe Document Server on the remote host uses the
default username and password to control access to its administrative
console.  Knowing these, an attacker can gain control of the affected
application." );
 script_set_attribute(attribute:"solution", value:
"Login via the administration interface and change the password for the
admin account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8019);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8019);

# Default credentials.
user = "admin";
pass = "adobe";

init_cookiejar();
# Check whether the login script exists.
r = http_send_recv3(method: 'GET', item:"/altercast/login.jsp", port:port);
if (isnull(r)) exit(0);

# If it does...
if ('<form name="loginForm" method="POST"' >< r[2])
{
  # Extract the cookie.
  cookie = get_http_cookie(name: "JSESSIONID");
  if (isnull(cookie)) exit(1);

  # Try to log in.
  postdata = string(
    "username=", user, "&",
    "password=", pass, "&",
    "submit=Sign+On"
  );
  r = http_send_recv3(method: 'POST', port: port, item: '/altercast/login.do',
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
   data: postdata, version: 11 );
  if (isnull(r)) exit(0);

  # There's a problem if we get a link to sign out.
  if ('<a href="logoff.jsp" class="navlink"' >< r[2])
  {
    security_hole(port);
    exit(0);
  }
}
