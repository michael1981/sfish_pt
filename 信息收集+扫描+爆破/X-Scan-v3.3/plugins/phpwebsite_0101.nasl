#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18636);
  script_version("$Revision: 1.10 $");

  script_bugtraq_id(14166, 14172);
  script_xref(name:"OSVDB", value:"17788");
  script_xref(name:"OSVDB", value:"17789");

  script_name(english:"phpWebSite <= 0.10.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection and directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpWebSite that suffers from
multiple flaws :

  - Multiple SQL Injection Vulnerabilities
    An attacker can affect database queries through the 
    parameters 'module' and 'mod' of the script 'index.php'.
    This may allow for disclosure of sensitive information,
    attacks against the underlying database, and the like.

  - A Directory Traversal Vulnerability
    An attacker can read arbitrary files on the remote host
    by using instances of the substring '../' in the 'mod' 
    parameter of the script 'index.php'." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcdab655" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78fbb69f" );
 script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor's advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detects multiple vulnerabilities in phpWebSite <= 0.10.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english: "CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("phpwebsite_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit one of the SQL injection flaws.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/index.php?",
      # nb: this should just produce a SQL syntax error.
      "module=", SCRIPT_NAME, "'&",
      "search_op=search&",
      "mod=all&",
      "query=1&",
      "search=Search" ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get a SQL error.
  if (
    egrep(
      string:res, 
      pattern:string("syntax error<.+ FROM mod_search WHERE module='", SCRIPT_NAME)
    )
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
