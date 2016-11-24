#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19335);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2460", "CVE-2005-2461", "CVE-2005-2462", "CVE-2005-2463");
  script_bugtraq_id(14425);
  script_xref(name:"OSVDB", value:"18395");
  script_xref(name:"OSVDB", value:"18396");
  script_xref(name:"OSVDB", value:"18397");
  script_xref(name:"OSVDB", value:"18398");
  script_xref(name:"OSVDB", value:"18399");

  script_name(english:"Kayako LiveResponse Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
variety of flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kayako LiveResponse, a web-based live
support system. 

The installed version of Kayako LiveResponse on the remote host fails
to sanitize user-supplied input to many parameters / scripts, which
makes the application vulnerable to SQL injection and cross-site
scripting attacks.  In addition, the application embeds passwords in
plaintext as part of GET requests and will reveal its installation
directory in response to direct calls to several scripts." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00092-07302005" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406914" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Kayako LiveResponse";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# A simple alert.
xss = "<script>alert(document.cookie);</script>";

test_cgi_xss(port: port, cgi: "/index.php", dirs: cgi_dirs(), sql_injection: 1,
 qs: strcat( "username=", urlencode(str:string('">', xss)), "&",
	     "password=", SCRIPT_NAME), 
 # There's a problem if we see our XSS as part of the LiveResponse 
 # login form.
  pass_str: strcat('input name=username type=text value="\">',xss) );
