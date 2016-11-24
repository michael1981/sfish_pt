#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18639);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2106");
  script_bugtraq_id(14110);
  script_xref(name:"OSVDB", value:"17647");

  script_name(english:"Drupal Public Comment/Posting Arbitrary PHP Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
arbitrary PHP code injection." );
 script_set_attribute(attribute:"description", value:
"The version of Drupal installed on the remote host, according to its
version number, allows attackers to embed arbitrary PHP code when
submitting a comment or posting. Note that successful exploitation
requires that public comments or postings be allowed in Drupal." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0290.html" );
 script_set_attribute(attribute:"see_also", value:"http://drupal.org/drupal-4.6.2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 4.5.4 / 4.6.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks version of Drupal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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
  ver = matches[1];

  # There's a problem if...
  if (
    # it's an affected version (ie, 4.5.0 - 4.5.3; 4.6.0 - 4.6.1) or...
    ver =~ "^4\.(5\.[0-3]|6\.[01])" ||
    # the version is unknown and report_paranoia is set to paranoid
    ("unknown" >< ver && report_paranoia > 1)
  ) {
    security_warning(port);
    exit(0);
  }
}
