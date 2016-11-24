#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17983);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1010");
  script_bugtraq_id(13000);
  script_xref(name:"OSVDB", value:"15240");

  script_name(english:"Comersus Cart Account Username Field XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Comersus Cart that fails to properly sanitize user input to the
'Username' field.  An attacker can exploit this vulnerability to cause
arbitrary HTML and script code to be executed by a user's browser in
the context of the affected web site when a user views the username;
eg, in the admin pages." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Comersus Cart newer than 6.03." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for username field HTML injection vulnerability in Comersus Cart");
  script_category(ACT_GATHER_INFO);
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
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Check various directories for Comersus Cart.
foreach dir (cgi_dirs()) {
  # Pull up customer registration form.
  r = http_send_recv3(method: 'GET', port: port,
   item: string(dir, "/comersus_customerRegistrationForm.asp"));
  if (isnull(r)) exit(0);

  # Make sure it's definitely Comersus Cart.
  if (
    egrep(string:r[2], pattern:"^<title>[^<]+ Powered by Comersus ASP Shopping Cart", icase:TRUE) ||
    egrep(string:r[2], pattern:'<link href="[^"]*images/comersus.css"', icase:TRUE)
  ) {
    # Check the version number - anything up to 6.03 may be vulnerable.
    pat = "([0-5]\\..+|6\\.0[0-3])[^0-9]";
    res = r[1]+'\r\n'+r[2];
    if (
      # version 6.x
      egrep(string:res, pattern:string("Powered by Comersus ", pat), icase:TRUE) ||
      # version 5.x
      egrep(string:res, pattern:string("StoreFront Version: ", pat), icase:TRUE) ||
      # version 4.x and early 5.0.x
      egrep(string:res, pattern:string("Comersus(</a>)? ", pat), icase:TRUE) ||
      # version 3.x
      egrep(string:res, pattern:string("based on Comersus ", pat), icase:TRUE) ||
      egrep(string:res, pattern:string(pat, "Cart Open Source"), icase:TRUE) ||
      egrep(string:res, pattern:'<a href="http://www.comersus.com.+images/powered3\\.gif', icase:TRUE)
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
