#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28334);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-6110");
  script_bugtraq_id(26610);
  script_xref(name:"OSVDB", value:"40229");

  script_name(english:"ht://dig htsearch sort Parameter XSS");
  script_summary(english:"Tries to exploit an XSS issue in htsearch");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The htsearch CGI script is accessible through the remote web server. 
htsearch is a component of ht://Dig used to index and search documents
such as web pages. 

The version of htsearch installed on the remote host fails to sanitize
user-supplied input to the 'sort' parameter before using it to
generate dynamic output.  An unauthenticated remote attacker may be
able to leverage this issue to inject arbitrary HTML or script code
into a user's browser to be executed within the security context of
the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8318aba2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

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
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
exss = urlencode(str:xss);


test_cgi_xss(port: port, cgi: "/htsearch", 
  qs: "config=&restrict=&exclude=&method=and&format=builtin-long&sort="
      +exss+"&words="+SCRIPT_NAME,
  pass_str: "No such sort method: `"+xss+"'", pass2_re: "ht://Dig");
