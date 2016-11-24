#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18372);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1308");
  script_bugtraq_id(13374);
  script_xref(name:"OSVDB", value:"15819");

  script_name(english:"SqWebMail redirect Parameter CRLF Injected XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SqWebMail that does not
properly sanitize user-supplied input through the 'redirect'
parameter.  An attacker can exploit this flaw to inject arbitrary HTML
and script code into a user's browser to be executed within the
context of the affected web site.  Such attacks could lead to session
cookie and password theft for users who read mail with SqWebMail." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0440.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for HTTP response splitting vulnerability in SqWebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# For each CGI directory...
test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/sqwebmail",
 qs: "redirect=%0d%0a%0d%0a"+SCRIPT_NAME,
 # There's a problem if there's a redirect
 pass_re:  '^Refresh: 0; URL="$',
 pass2_re: string("^", SCRIPT_NAME, "$"));
