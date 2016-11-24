#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# - Revised plugin title (4/3/2009)
# - Updated to use compat.inc, Added CVSS score, Revised description, Fixed severity (11/18/2009)


include("compat.inc");

if (description) {
  script_id(19748);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2005-2404");
  script_bugtraq_id(14351);
  script_xref(name:"OSVDB", value:"18153");

  script_name(english:"Sendcard sendcard.php id Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webserver has a PHP script that is affected by a 
SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sendcard, a multi-database e-card program written 
in PHP.

The version of Sendcard installed on the remote host is prone to a SQL
injection attack due to its failure to sanitize user-supplied input to
the 'id' field in the 'sendcard.php' script." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_summary(english:"Checks for SQL injection in the id field in sendcard.php");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005-2009 Josh Zlatin-Amishav");

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/sendcard.php?",
     "view=1&",
     "id=%27", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
       ( "SELECT \* FROM sendcard where id='" + SCRIPT_NAME) >< res  &&
         "MySQL Error" >< res
     ) 
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
