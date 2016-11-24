#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17350);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0783", "CVE-2005-0784");
  script_bugtraq_id(12800);
  script_xref(name:"OSVDB", value:"14823");
  script_xref(name:"OSVDB", value:"14824");
  script_xref(name:"OSVDB", value:"14660");

  script_name(english:"Phorum < 5.0.15 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from multiple
cross-site scripting flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Phorum installed on the remote host is prone to
multiple cross-site scripting vulnerabilities due to its failure to
sanitize user input.  An attacker can exploit these flaws to
potentially cause arbitrary script and HTML code to be rendered by a
user's browser in the context of the vulnerable site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393192" );
 script_set_attribute(attribute:"see_also", value:"http://www.phorum.org/story.php?48" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Phorum 5.0.15 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple subject and attachment cross-site scripting and HTML injection vulnerabilities in Phorum";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencies("phorum_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
#
# nb: actually testing for this is difficult because each forum can be
#     configured to allow anonymous users to create new threads, reply
#     to existing ones, and/or upload files and, by default in at
#     at least 5.0.15, these 3 settings are disabled.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: Bugtraq advisory says 5.0.14 and possibly earlier are affected.
  if (ver =~ "^([0-4].*|5\.0\.([0-9][^0-9]*|1[0-4][^0-9]*))$")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
