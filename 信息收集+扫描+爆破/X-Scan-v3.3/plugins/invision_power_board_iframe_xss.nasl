#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17609);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0886");
  script_bugtraq_id(12888);
  script_xref(name:"OSVDB", value:"16604");

  script_name(english:"Invision Power Board HTTP POST Request IFRAME Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Invision Power Board installed on the remote host does
not properly sanitize HTML tags, which enables a remote attacker to
inject a malicious IFRAME when posting a message to one of the hosted
forums.  This could cause arbitrary HTML and script code to be
executed in the context of users browsing the forum, which may enable
an attacker to steal cookies or misrepresent site content." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Power Board 2.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for IFRAME HTML Injection Vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.|2\.0\.[0-2][^0-9]*)")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
