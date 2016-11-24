#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29746);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-6587");
  script_bugtraq_id(26958);
  script_xref(name:"OSVDB", value:"39764");

  script_name(english:"Plogger plog-rss.php id Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Plogger, an open-source photo
gallery written in PHP. 

The version of Plogger installed on the remote host fails to sanitize
input to the 'id' parameter of the 'plog-rss.php' script before using
it in a database query.  Regardless of PHP's 'magic_quotes_gpc' and
'register_globals' settings, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, modification of data, or attacks against the
underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69f2c406" );
 script_set_attribute(attribute:"see_also", value:"http://dev.plogger.org/changeset/489" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Plogger 1.0 beta 3.0 if necessary and apply change set 489." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/plogger", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to generate a SQL error.
  exploit = string("999 OR ", SCRIPT_NAME);

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/plog-rss.php?",
      "level=collection&",
      "id=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a SQL error involving our exploit
  if (string("WHERE p.`parent_collection` = ", exploit) >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
