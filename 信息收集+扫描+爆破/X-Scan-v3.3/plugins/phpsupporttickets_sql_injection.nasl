#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20378);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-4264");
  script_bugtraq_id(15853);
  script_xref(name:"OSVDB", value:"21730");

  script_name(english:"PHP Support Tickets index.php Multiple Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in PHP Support Tickets");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Support Tickets, an open-source support
ticketing system written in PHP. 

The installed version of PHP Support Tickets does not validate input
to the 'username' or 'password' parameters of the 'index.php' script
before using it in a database query.  An attacker may be able to
leverage this issue to manipulate SQL queries to, for example, bypass
authentication and gain administrative access to the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.nii.co.in/vuln/PHPSupportTickets.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor as reportedly there is a patch to fix the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/phpsupporttickets", "/helpdesk", "/support", "/tickets", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check the main index.php page.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  # If it looks like PHP Support Tickets' login form...
  if (
    '<input type="hidden" name="login"' >< res &&
    'Username <input name="username"' >< res &&
    ">PHP Support Tickets v" >< res
  ) {
    # Try to exploit the flaw to get a syntax error.
    postdata = string(
      "login=login&",
      "page=login&",
      "username='", SCRIPT_NAME, "&",
      "password=nessus&",
      "form=Log+In"
    );
    r = http_send_recv3(method: "POST ", item: dir + "/index.php", version: 11, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if we get a syntax error involving our script name.
    if (
      "an error in your SQL syntax" >< res &&
      string("departments.ID AND username = ''", SCRIPT_NAME) >< res
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}

