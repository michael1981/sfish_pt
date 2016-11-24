#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18011);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1070");
  script_bugtraq_id(13097);
  script_xref(name:"OSVDB", value:"15496");

  script_name(english:"Invision Power Board index.php Members Action st Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"A version of Invision Power Board installed on the remote host suffers
from a SQL injection vulnerability due to its failure to sanitize user
input via the 'st' parameter to the 'index.php' script.  An attacker
can take advantage of this flaw to inject arbitrary SQL statements
into Invision Power Board, possibly even modifying the database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/395515" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for st parameter SQL injection vulnerability in Invision Power Board";
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

  # Try to exploit it.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "act=Members&", 
      "max_results=30&",
      "filter=1&",
      "sort_order=asc&",
      "sort_key=name&",
      # nb: the 'st' parameter is used in a SELECT statement as the offset in
      #     a LIMIT clause so appending a '--' will cause a syntax error
      #     since it tells MySQL to ignore the rest of the statement.
      "st=1--"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("<title>Invision Power Board Database Error" >< res) 
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
