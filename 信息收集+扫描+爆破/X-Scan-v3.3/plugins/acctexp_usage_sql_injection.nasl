#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32505);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(29466);
  script_xref(name:"milw0rm", value:"5721");

  script_name(english:"AEC Subscription Manager Component usage Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of the AEC Subscription Manager component for Joomla and
Mambo installed on the remote host fails to sanitize user-supplied
input to the 'usage' parameter before using it in database queries in
'acctexp.class.php'.  Regardless of PHP's 'magic_quotes_gpc' setting,
an attacker may be able to exploit this issue to manipulate database
queries, leading to disclosure of sensitive information, modification
of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
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


# Generate a list of paths to check.
dirs = make_list();

# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the issue to generate a SQL error.
  exploit = string(unixtime(), " OR ", SCRIPT_NAME);

  r = http_send_recv3(method:"GET", port:port,
    item:string(dir, "/index.php?",
      "option=com_acctexp&",
      "task=subscribe&", "usage=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a SQL error involving the acctexp_plans table.
  if (
    "DB function failed" >< res &&
    string("acctexp_plans WHERE active = '1' AND id=", exploit) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
