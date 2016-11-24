#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29995);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-0358");
  script_bugtraq_id(27242);
  script_xref(name:"OSVDB", value:"40299");

  script_name(english:"Pixelpost index.php parent_id Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Pixelpost, a photo blog application based
on PHP and MySQL. 

The version of Pixelpost installed on the remote host fails to
sanitize input to the 'parent_id' parameter of the 'index.php' script
before using it to perform database queries.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an attacker may be able to
exploit this issue to manipulate database queries to disclose
sensitive information, bypass authentication, modify data, or even
attack the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4924" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
if (thorough_tests) dirs = list_uniq(make_list("/pixelpost", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Ensure we're looking at Pixelpost.
  url = string(dir, "/index.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it is...
  if ('"Pixelpost' >< res)
  {
    # Try to exploit the issue to generate a syntax error.
    exploit = string(rand(), "'", SCRIPT_NAME);

    postdata = string(
      "parent_id='", exploit
    );
    r = http_send_recv3(method: "POST ", item: url+"?popup=comment", version: 11, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];
    # There's a problem if we see an error message with our script name.
    if (string("right syntax to use near '", exploit, "'") >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
