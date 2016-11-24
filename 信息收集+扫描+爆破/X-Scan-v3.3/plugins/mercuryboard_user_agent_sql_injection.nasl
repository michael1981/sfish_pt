#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18541);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2028");
  script_bugtraq_id(14015);
  script_xref(name:"OSVDB", value:"17406");

  script_name(english:"MercuryBoard User-Agent SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MercuryBoard, an open-source bulletin board
system that uses PHP and MySQL. 

The installed version of MercuryBoard fails to remove malicious data
from a User-Agent header before using it in a database query, making
it prone to SQL injection attacks.  An authenticated attacker can
exploit this flaw to modify database updates, possibly modifying data
and launching attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402929/30/0/" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for User-Agent remote SQL injection vulnerability in MercuryBoard";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  req = string(
    "GET ", dir, "/index.php HTTP/1.1\r\n",
    "User-Agent: ", SCRIPT_NAME, "'\r\n",
    "Host: ", get_host_name(), "\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # It looks like MercuryBoard and...
    "<title>MercuryBoard Error</title>" >< res && 
    # We see a syntax error with our script name.
    egrep(string:res, pattern:string("Query.+REPLACE INTO.+'", SCRIPT_NAME, "''"))
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
