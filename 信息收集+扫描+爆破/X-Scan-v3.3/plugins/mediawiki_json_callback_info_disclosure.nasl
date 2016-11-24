#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31346);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1318");
  script_bugtraq_id(28070);
  script_xref(name:"OSVDB", value:"42588");
  script_xref(name:"Secunia", value:"29216");

  script_name(english:"MediaWiki JSON Callback Crafted API Request Information Disclosure");
  script_summary(english:"Requests an edittoken with a JSON callback");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of MediaWiki installed on the remote host may disclose
sensitive information when its API processes a JSON callback because
it allows cross-site reads." );
 script_set_attribute(attribute:"see_also", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2008-March/000070.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.11.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
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


# Loop through various directories.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Request an edittoken.
  callback = string("nessus", unixtime());

  req = http_get(
    item:string(
      dir, "/api.php?",
      "action=query&",
      "prop=info&",
      "intoken=edit&",
      "titles=Main_Page&",
      "format=json&",
      "callback=", callback
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # our callback function was returned and...
    string(callback, '({"error":') >< res &&
    # we see an error saying the edit is not allowed
    "Action 'edit' is not allowed for the current user" >< res
  )
  {
    security_warning(port);
    exit(0);
  }
}
