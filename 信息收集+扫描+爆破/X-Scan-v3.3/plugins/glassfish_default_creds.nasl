#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38701);
  script_version("$Revision: 1.3 $");

  script_name(english: "Sun Glassfish Default Administrator Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server uses default credentials." );
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Sun Glassfish administration
console by providing default credentials.  Knowing these, an attacker
can gain administrative control of the affected application server
and, for example, install hostile applets.");
  script_set_attribute(attribute: "solution", value: "Change the admin password.");
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_end_attributes();
  script_summary(english: "Log on Glassfish with admin/adminadmin");
  script_category(ACT_ATTACK);
  script_copyright( english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 4848);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 4848, embedded: 0);

banner = get_http_banner(port:port);
if (banner && "Sun GlassFish Enterprise Server" >!< banner) exit(0);

# Clear the cookies, in case Nessus was given credentials
clear_cookiejar();

# Get the session cookie
r = http_send_recv3(port: port, method: "GET",item: "/login.jsf");
if (r[0] =~ '^HTTP/1\\.[01] + 200 ') exit(0);

user = "admin"; pass = "adminadmin";

r = http_send_recv3(port: port, method: "POST",
   item: "/j_security_check?loginButton=Login",
   add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
   follow_redirect: 1,
   data: "j_username="+user+"&j_password="+pass+"&loginButton.DisabledHiddenField=true");

if ( r[0] =~ '^HTTP/1\\.[01] +200 ' && 
     egrep(string: r[2], pattern: '<frameset id="outerFrameset" title="Sun GlassFish Enterprise Server v[0-9.]+ Admin Console"'))
  security_hole(port: port, extra: strcat("\nNessus could log with ", user, "/", pass, "."));
