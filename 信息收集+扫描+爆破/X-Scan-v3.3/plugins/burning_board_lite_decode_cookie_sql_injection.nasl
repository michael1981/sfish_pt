#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(23733);
  script_version ("$Revision: 1.9 $");

  script_cve_id("CVE-2006-6237");
  script_xref(name:"OSVDB", value:"30681");

  script_name(english:"WoltLab Burning Board Lite thread.php decode_cookie Function threadvisit Cookie Variable SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in Burning Board Lite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote version of Burning Board Lite fails to sanitize user-
supplied cookie input before using it in the 'decode_cookie()'
function in a database query.  Regardless of PHP settings, an
unauthenticated attacker may be able to leverage this issue to uncover
sensitive information (such as password hashes), modify existing data,
or launch attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/wbblite_102_sql_mqg_bypass.html" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2841" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("burning_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test any installs.
install = get_kb_list(string("www/", port, "/burning_board_lite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # First we need a thread id.
  idx = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(idx)) exit(0);

  pat = '<a href="thread\\.php\\?.*threadid=([0-9]+)';
  matches = egrep(pattern:pat, string: idx);
  tid = NULL;
  if (matches) 
  {
    foreach match (split(matches)) 
    {
      match = chomp(match);
      thread = eregmatch(pattern:pat, string:match);
      if (!isnull(thread)) {
        tid = thread[1];
        break;
      }
    }
  }

  # If we have a thread id.
  if (isnull(tid))
  {
    debug_print("couldn't find a thread id to use!", level:0);
  }
  else 
  {
    # Try to exploit the flaw to generate a SQL error.
    set_http_cookie( name: "threadvisit", 
    		     value: strcat("1,999999999999999'", SCRIPT_NAME));
    r = http_send_recv3(port:port, method: 'POST', version: 11,
 item: strcat(dir, "/thread.php?threadid=", tid), data: "goto=firstnew",
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
    if (isnull(r)) exit(0);

    # There's a problem if we see a database error with our script name.
    res = r[1]+r[2];
    if (
      "SQL-DATABASE ERROR" >< res &&
      string("posttime>'999999999999999'", SCRIPT_NAME) >< res
    ) {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
