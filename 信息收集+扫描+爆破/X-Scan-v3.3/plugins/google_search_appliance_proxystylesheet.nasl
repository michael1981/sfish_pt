#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20241);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-3754", "CVE-2005-3755", "CVE-2005-3756", "CVE-2005-3757", "CVE-2005-3758");
  script_bugtraq_id(15509);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"20977");
    script_xref(name:"OSVDB", value:"20978");
    script_xref(name:"OSVDB", value:"20979");
    script_xref(name:"OSVDB", value:"20980");
    script_xref(name:"OSVDB", value:"20981");
  }

  script_name(english:"Google Search Appliance proxystylesheet Parameter Multiple Remote Vulnerabilities (XSS, Code Exec, ID)");
  script_summary(english:"Checks for proxystylesheet parameter multiple vulnerabilities in Google Search Appliance");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Google Search Appliance / Mini Search Appliance fails to
sanitize user-supplied input to the 'proxystylesheet' parameter, which
is used for customization of the search interface.  Exploitation of
this issue may lead to arbitrary code execution (as an unprivileged
user), port scanning, file discovery, and cross-site scripting." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7135810e" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-November/038940.html" );
 script_set_attribute(attribute:"solution", value:
"Contact Google for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("google_search_appliance_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_kb_item(string("www/", port, "/google_search_appliance"))) exit(0);


file = "../../../../../../../../../../etc/passwd";
w = http_send_recv3(method:"GET",
  item:string(
    "/search?",
    "site=nessus&",
    "output=xml_no_dtd&",
    "q=", SCRIPT_NAME, "&",
    "proxystylesheet=", file
  ), 
  port:port
);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];

# There's a problem if the error message indicates...
if (
  # the file doesn't exist or...
  string("ERROR: Unable to fetch the stylesheet from source: ", file) >< res ||
  # the file does exist but isn't a valid stylesheet.
  "The following required pattern was not found:" >< res
) {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
