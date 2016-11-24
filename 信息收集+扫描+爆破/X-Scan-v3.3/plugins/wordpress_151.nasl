#
# (C) Tenable Network Security
#
# 


include("compat.inc");

if (description) {
  script_id(18301);
  script_version("$Revision: 1.6 $");
  script_bugtraq_id(13655, 13663, 13664);

  name["english"] = "WordPress < 1.5.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains multiple PHP scripts that are prone to
SQL injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host suffers from
multiple vulnerabilities:

  - A SQL Injection Vulnerability
    WordPress fails to properly sanitize user input passed 
    via the 'tb_id' parameter to the 'wp-trackback.php'
    script before using it in database queries. This 
    could lead to disclosure of sensitive information or
    even attacks against the underlying database.

  - Multiple Cross-Site Scripting Vulnerabilities.
    An attacker can pass arbitrary HTML and script code
    through the 's' parameter of the 'wp-admin/edit.php' 
    script or the 'p' parameter in the 'wp-admin/post.php' 
    script, thereby facilitating cross-site scripting
    attacks. Note, though, that these attacks will
    only be successful against administrators since the
    scripts themselves are limited to administrators." );
 script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2005/05/one-five-one/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in WordPress < 1.5.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencie("wordpress_detect.nasl");
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
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try a SQL injection.
  postdata = string(
    # nb: this should lead to a syntax error.
    "tb_id=-99'", SCRIPT_NAME, "&",
    "url=http://wordpress.org/development/2005/05/one-five-one/&",
    "title=", SCRIPT_NAME, "&",
    "blog_name=Nessus"
  );
  req = string(
    "POST ", dir, "/wp-trackback.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a database error with the plugin's name.
  if (
    "<p class='wpdberror'>" >< res &&
    string("FROM wp_posts WHERE ID = -99'", SCRIPT_NAME) >< res
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }

  # Alert on the version number in case magic_quotes was enabled.
  if (ver =~ "^(0\.|1\.([0-4]|5([^0-9.]+|$|\.0)))") {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
