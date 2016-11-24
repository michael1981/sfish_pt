#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17247);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0632");
  script_bugtraq_id(12696);
  script_xref(name:"OSVDB", value:"14313");

  script_name(english:"PHPNews auth.php path Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from a remote
file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPNews, an open-source news application
written in PHP. 

The installed version of PHPNews has a remote file include
vulnerability in the script 'auth.php'.  By leveraging this flaw, a
attacker can cause arbitrary PHP code to be executed on the remote
host using the permissions of the web server user." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0026.html" );
 script_set_attribute(attribute:"see_also", value:"http://newsphp.sourceforge.net/changelog/changelog_1.25.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPNews 1.2.5 or greater or make sure PHP's
'register_globals' and 'allow_url_fopen' settings are disabled." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detects remote file include vulnerability in auth.php in PHPNews";
  script_summary(english:summary["english"]);
 
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpnews", "/news", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  # If the main page is from PHPNews...
  if ('<link href="phpnews_package.css"' >< res) {
    # Try the exploit by grabbing the site's PHPNews phpnews_package.css.
    exploit = string("/auth.php?path=http://", get_host_name(), dir, "/phpnews_package.css%00");
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # If it looks like we got a stylesheet, there's a problem.
    if ("a:link {" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
