#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18430);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1888");
  script_bugtraq_id(13861);
  script_xref(name:"OSVDB", value:"17107");

  script_name(english:"MediaWiki Page Template Inclusions HTML Attributes XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of Mediawiki installed on
the remote host is vulnerable to cross-site scripting attacks because
of its failure to sanitize input passed to certain HTML attributes by
including a template inside a style directive when editing an entry. 
An attacker can leverage this flaw to inject arbitrary HTML and script
code to be executed by a user's browser within the context of an
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://bugzilla.wikimedia.org/show_bug.cgi?id=2304" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.3.13 or later if using 1.3 legacy series;
otherwise, switch to 1.4.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for page template cross-site scripting vulnerability in MediaWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|1[0-2])|4\.[0-4]($|[^0-9.])|5 alpha1)") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
