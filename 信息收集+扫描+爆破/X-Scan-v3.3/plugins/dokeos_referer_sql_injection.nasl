#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31116);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0850");
  script_bugtraq_id(27792);
  script_xref(name:"OSVDB", value:"41701");
  script_xref(name:"Secunia", value:"28974");

  script_name(english:"Dokeos main/inc/lib/events.lib.inc.php Referer HTTP Header SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dokeos, an open-source, e-learning and
course management web application written in PHP. 

The version of Dokeos installed on the remote host fails to sanitize
user input to the 'Referer' request header before using it in the
'main/inc/lib/events.lib.inc.php' script to perform database queries. 
Regardless of PHP's 'magic_quotes_gpc' setting, an attacker may be
able to exploit this issue to manipulate database queries to disclose
sensitive information, or even attack the underlying database. 

Note that there are also reportedly several other vulnerabilities
associated with this version of Dokeos, although Nessus has not
checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://projects.dokeos.com/index.php?do=details&task_id=2218" );
 script_set_attribute(attribute:"solution", value:
"Apply Dokeos 1.8.4 SP2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/dokeos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to generate a SQL error.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port,
    add_headers: make_array("Referer", "'" + SCRIPT_NAME) );
  if (isnull(r)) exit(0);

  # There's a problem if we get a syntax error
  if (
    "main/inc/lib/events.lib.inc.php" >< r[2] &&
    (
      "SQL error" >< r[2] ||
      string("syntax to use near '", SCRIPT_NAME) >< r[2]
    )
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
