#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18029);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1188");
  script_bugtraq_id(13125);
  script_xref(name:"OSVDB", value:"15539");

  script_name(english:"Comersus Cart comersus_searchItem.asp curPage Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Comersus Cart installed on the remote host fails to
properly sanitize user input to the 'curPage' parameter of the
'comersus_searchItem.asp' script.  An attacker can exploit this
vulnerability to cause arbitrary HTML and script code to be executed
in a user's browser within the context of the affected web site when a
user views a malicious link." );
 script_set_attribute(attribute:"see_also", value:"http://lostmon.blogspot.com/2005/04/comersus-asp-shopping-cart-variable.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Comersus Cart version 6.00 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for comersus_searchItem.asp cross-site scripting vulnerability in Comersus Cart";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Check various directories for Comersus Cart.
foreach dir (cgi_dirs()) {
  # Try the exploit.
  r = http_send_recv3(method: 'GET', port: port,
   item:string(dir, "/comersus_searchItem.asp%22%3E", exss));
  if (isnull(r)) exit(0);

  # Make sure it's definitely Comersus Cart.
  if (
    egrep(string: r[2], pattern:"^<title>[^<]+ Powered by Comersus ASP Shopping Cart", icase:TRUE) ||
    egrep(string: r[2], pattern:'<link href="[^"]*images/comersus.css"', icase:TRUE)
  ) {
    # If we see our XSS, there's a problem.
    if (xss >< res) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}

