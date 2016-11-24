#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27802);
  script_version("$Revision: 1.4 $");

  script_name(english:"HP OpenView Client Configuration Manager Default Credentials");
  script_summary(english:"Tries to login to OVCCM with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP OpenView Client Configuration Manager
(OVCCM), a PC software configuration management application. 

The remote installation of OVCCM is configured to use default
credentials to control access.  Knowing these, an attacker can gain
control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' account by logging into OVCCM,
navigating to 'Configuration / Console Access', and editing the
'admin' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3480);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3480);

user = "admin";
pass = "secret";

init_cookiejar();
# Check whether the login script exists.
url = "/ccm/console.tcl?";
r = http_send_recv3(method: "GET", item:url, port:port);
if (isnull(r)) exit(0);

# If it does...
if ('<input name="user.id"' >< r[2])
{
  # Extract the session identifier.
  sid = NULL;
  pat = 'name="sessionId" value="([^"]+)">';
  matches = egrep(pattern:pat, string:r[2]);
  if (matches)
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      value = eregmatch(pattern:pat, string:match);
      if (!isnull(value))
      {
        sid = value[1];
        break;
      }
    }
  }
  if (isnull(sid))
  {
    debug_print("can't extract the session identifier!");
    exit(1);
  }

  # Try to log in.
  postdata = string(
    "user.id=", user, "&",
    "user.password=", pass, "&",
    "btnSignIn:btnCommandButton=Sign+In&",
    "login=1&",
    "sessionId=", sid, "&",
    "referal="
  );
  r = http_send_recv3(method: "POST", item: url, data: postdata, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);

  # There's a problem if the admin cookie is set.
  if (string(';URL=?sessionId=', sid) >< r[1]+r[2] &&
      egrep(pattern:"Set-Cookie: user.token=[^;]+;", string:r[1]) )
  {
      report = string(
      "Nessus was able to gain access using the following credentials :\n",
      "\n",
      "  User     : ", user, "\n",
      "  Password : ", pass, "\n"
      );
      security_hole(port:port, extra:report);
  }
}
