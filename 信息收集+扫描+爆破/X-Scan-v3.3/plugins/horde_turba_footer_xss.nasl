#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18138);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1315");
  script_xref(name:"OSVDB", value:"15764");

  script_name(english:"Horde Turba common-footer.inc Parent Frame Page Title XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of Turba fails to
fully sanitize user-supplied input when setting the parent frame's
page title by javascript in 'templates/common-footer.inc'.  By
leveraging this flaw, an attacker may be able to inject arbitrary HTML
and script code into a user's browser to be executed in the context of
the affected web site, thereby resulting in the theft of session
cookies and similar attacks." );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/announce/2005/000200.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Turba 1.2.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for cross-site scripting vulnerability in Turba common-footer.inc";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("horde_turba_detect.nasl");
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
install = get_kb_item(string("www/", port, "/horde_turba"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0|1\.([01]|2$|2\.[0-4]([^0-9]|$)))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
