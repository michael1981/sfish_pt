#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18222);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-2805");
  script_bugtraq_id(13572, 13573, 13576, 13577, 13974, 14301, 14495, 14508, 14699);
  script_xref(name:"OSVDB", value:"17569");
  script_xref(name:"OSVDB", value:"17571");
  script_xref(name:"OSVDB", value:"17572");
  script_xref(name:"OSVDB", value:"17573");
  script_xref(name:"OSVDB", value:"17574");
  script_xref(name:"OSVDB", value:"17616");
  script_xref(name:"OSVDB", value:"17617");

  script_name(english:"e107 < 7.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of e107 installed on the remote host contains a large
number of vulnerabilities, including global variable updates, remote
file includes, directory traversal, information disclosure, cross-site
scripting, and SQL injection vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://e107.org/e107_plugins/bugtrack/bugtrack.php?action=show&id=558" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402469/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/id.php?id=1106" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407582" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to e107 version 7.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in e107 <= 0.617";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
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
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # Identify a stylesheet for use in the exploit.
  pat = '<link rel="stylesheet" href="([^:]+/e107\\.css)"';
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      file = eregmatch(pattern:pat, string:match);
      if (!isnull(file)) {
        file = file[1];

        # Try to exploit the file include vuln to read the stylesheet; yes
        # it's lame, but it does prove whether the vulnerability exists.
        postdata = string(
          "searchquery=aaa&",
          "search_info[0][sfile]=./", file, "&",
          "searchtype[0]=0",
          "searchtype[1]=0"
        );
        r = http_send_recv3(method: "POST ", item: dir + "/search.php", port: port,
	  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	  data: postdata);
        if (isnull(r)) exit(0);
	res = r[2];

        if ("e107 website system" >< res) {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }
      }
    }
  }
}
