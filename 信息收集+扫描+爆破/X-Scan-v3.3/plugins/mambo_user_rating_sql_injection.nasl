#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18495);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2002");
  script_bugtraq_id(13966, 14117, 14119);

  name["english"] = "Mambo Open Source < 4.5.2.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installed version of Mambo Open Source on the remote host suffers
from the following flaws :

  - Session ID Spoofing Vulnerability
    An unspecified flaw in the script 'administrator/index3.php'
    can be exploited to spoof session IDs.

  - Local File Disclosure Vulnerability
    The 'includes/DOMIT/testing_domit.php' script may be used
    to read the contents of local files such as Mambo's
    configuration file, which holds database credentials.

  - A SQL Injection Vulnerability
    The application fails to properly sanitize user-supplied 
    input to the 'user_rating' parameter of the 
    'components/com_content/content.php' script before using 
    it in SQL statements.

  - Multiple Unspecified Injection Vulnerabilities
    Various class 'check' methods fail to properly
    sanitize input, although it's unknown precisely
    what dangers these flaws present." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034575.html" );
 script_set_attribute(attribute:"see_also", value:"http://mamboforge.net/frs/download.php/6153/CHANGELOG" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo version 4.5.2.3 or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Mambo Open Source < 4.5.2.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
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
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the SQL injection flaw.
  #
  # nb: randomize CID to avoid already voted problems.
  cid = rand() % 100;
  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=com_content&",
      "task=vote&",
      "id=1&",
      "Itemid=1&",
      "cid=", cid, "&",
      # this just produces a syntax error in a vulnerable version.
      "user_rating=1'", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error mentioning this plugin.
  if (
    "DB function failed with error number 1064" >< res &&
    string("right syntax to use near '", SCRIPT_NAME, "', '") >< res
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
