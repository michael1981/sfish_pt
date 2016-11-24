#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18447);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1948");
  script_bugtraq_id(13907);
  script_xref(name:"OSVDB", value:"17243");
  script_xref(name:"OSVDB", value:"17244");

  script_name(english:"Invision Gallery < 1.3.1 Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application is vulnerable to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Gallery, a community-based photo
gallery plugin for Invision Power Board. 

The version installed on the remote host fails to properly sanitize
user-supplied data through several parameters, making it prone to
multiple SQL injection and cross-site scripting vulnerabilities. 
These flaws may allow an attacker to delete images and/or albums,
discover password hashes, and even affect UPDATE database queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00079-06092005" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Gallery 1.3.1 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Invision Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
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
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection vulnerabilities.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "act=module&",
      "module=gallery&",
      "cmd=editcomment&",
      # nb: look for this exploit string later.
      "comment='", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "an error in your SQL syntax" >< res &&
    egrep(
      string:res, 
      pattern:string("SELECT \* FROM .*gallery_comments WHERE pid=&amp;#39;", SCRIPT_NAME)
    )
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
