#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27526);
  script_version("$Revision: 1.5 $");

  script_name(english:"CA Host-Based Intrusion Prevention System Server Default Credentials");
  script_summary(english:"Tries to login to CA HIPS with default credentials");

 script_set_attribute(attribute:"synopsis", value:
"The remote web service is protected with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Computer Associates' Host-Based Intrusion
Prevention System (CA HIPS) Server, an intrusion prevention system for
Windows. 

The remote installation of CA HIPS Server is configured to use default
credentials to control access.  Knowing these, an attacker can gain
control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' account by logging into the CA
HIPS server, navigating to 'Global Settings / Administrators', and
editing the 'admin' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:1443);

init_cookiejar();

user = "admin";
pass = "admin";


# Check whether the login script exists.
url = "/hss/hss";
r = http_send_recv3(method: 'GET', item: "/hss/hss?pg=login.ftl", port:port);
if (isnull(r)) exit(0);


# If it does...
if ('<form  id="_AuthLogin"' >< r[2])
{
  # Extract the session identifier.
  sid = NULL;
  pat = 'action="/hss/hss\\?s=([^&]+)&cm=AuthLogin"';
  matches = egrep(pattern:pat, string: r[2]);
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
    "redir_e=login.ftl&",
    "redir=main.ftl&",
    "sessionOnly=false&",
    "loginName=", user, "&",
    "password=", pass, "&",
    "submit=Login"
  );
  r = http_send_recv3(port:port, method: 'POST', version: 11, 
 item: strcat(url, "?s=", sid, "&cm=AuthLogin"), data: postdata,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);

  # There's a problem if the admin cookie is set.
  if ("Set-Cookie: HIPS_S_" >< r[1] && r[1] =~ "Set-Cookie: HIPS_S_[0-9]+=admin")
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
