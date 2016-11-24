#
# (C) Tenable Network Security, Inc.
# 



include("compat.inc");

if (description) {
  script_id(18644);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2215");
  script_bugtraq_id(14181);
  script_xref(name:"OSVDB", value:"17763");

  script_name(english:"MediaWiki Page Move Template XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to cross-
site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of Mediawiki installed on
the remote host is vulnerable to cross-site scripting attacks because
of its failure to sanitize input passed to the page move template. 
This flaw could be used to inject arbitrary HTML and script code into
a user's browser resulting in the theft of cookies, misrepresentation
of the site, and other such attacks." );
 script_set_attribute(attribute:"see_also", value:"http://bugzilla.wikimedia.org/show_bug.cgi?id=2304" );
 script_set_attribute(attribute:"solution", value:
"If using MediaWiki 1.4.x, upgrade to 1.4.6 or later; if using MediaWiki
1.5.x, upgrade to 1.5.0 beta3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for page move template cross-site scripting vulnerability in MediaWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
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
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.(4\.[0-5]($|[^0-9.])|5.* (alpha|beta[12]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
