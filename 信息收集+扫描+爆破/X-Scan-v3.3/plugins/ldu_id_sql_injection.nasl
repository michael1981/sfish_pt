#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23782);
  script_version ("$Revision: 1.11 $");

  script_cve_id("CVE-2006-6343", "CVE-2006-6577");
  script_bugtraq_id(21366);
  script_xref(name:"OSVDB", value:"31712");
  script_xref(name:"OSVDB", value:"32036");

  script_name(english:"Land Down Under / Seditio polls.php id Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in Land Down Under / Seditio");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of Land Down Under or Seditio fails to sanitize
input to the 'id' parameter of the 'polls.php' script before using it
in a database query.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an unauthenticated attacker may be able to leverage this
issue to uncover sensitive information (such as password hashes),
modify existing data, or launch attacks against the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2871" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("ldu_detection.nasl", "seditio_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test any installs.
kb1 = get_kb_list(string("www/", port, "/ldu"));
if (isnull(kb1)) kb1 = make_list();
else kb1 = make_list(kb1);

kb2 = get_kb_list(string("www/", port, "/seditio"));
if (isnull(kb2)) kb2 = make_list();
else kb2 = make_list(kb2);

installs = make_list(kb1, kb2);
foreach install (installs)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];

    # Try to exploit the flaw to cause a SQL error.
    req = http_get(
      item:string(
        dir, "/polls.php?",
        "id='", SCRIPT_NAME
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a database error with our script name.
    if (
      "MySQL error" >< res &&
      string("'", SCRIPT_NAME, "' AND poll_state=0") >< res
    ) 
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}

