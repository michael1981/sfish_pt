#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18139);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1319");
  script_xref(name:"OSVDB", value:"15782");

  script_name(english:"IMP common-footer.inc Parent Frame Page Title XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of IMP fails to fully
sanitize user-supplied input when setting the parent frame's page title
by javascript in 'templates/common-footer.inc'.  By leveraging this
flaw, an attacker may be able to inject arbitrary HTML and script code
into a user's browser to be executed in the context of the affected web
site, thereby resulting in the theft of session cookies and similar
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://lists.horde.org/archives/imp/Week-of-Mon-20050418/041912.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IMP 3.2.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for cross-site scripting vulnerability in IMP common-footer.inc";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("imp_detect.nasl");
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
install = get_kb_item(string("www/", port, "/imp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([0-2]|3\.([01]|2$|2\.[0-7]([^0-9]|$)))")
  {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
