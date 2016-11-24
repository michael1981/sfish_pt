#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17971);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-0994", "CVE-2005-0995");
  script_bugtraq_id(12990);
  script_xref(name:"OSVDB", value:"15263");
  script_xref(name:"OSVDB", value:"15264");
  script_xref(name:"OSVDB", value:"15266");
  script_xref(name:"OSVDB", value:"15268");

  script_name(english:"ProductCart Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by
several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ProductCart shopping cart
software that suffers from several input validation vulnerabilities:

  - SQL Injection Vulnerabilities
    The 'advSearch_h.asp' script fails to sanitize user input to
    the 'idCategory', and 'resultCnt' parameters, allowing an
    attacker to manipulate SQL queries.

  - Multiple Cross-Site Scripting Vulnerabilities
    The application fails to sanitize user input via the 
    'redirectUrl' parameter of the 'NewCust.asp' script, the
    'country' parameter of the 'storelocator_submit.asp' script,
    the 'error' parameter of the 'techErr.asp' script, and the 
    'keyword' parameter of the 'advSearch_h.asp' script before
    using it in dynamically generated web content. An attacker
    can exploit these flaws to cause arbitrary HTML and script
    code to be executed in a user's browser in the context of 
    the affected website." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks for multiple input validation vulnerabilities in ProductCart";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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
if (!can_host_asp(port:port)) exit(0);


# Check various directories for ProductCart.
foreach dir (cgi_dirs()) {
  # Try to pull up ProductCart's search page.
  r = http_send_recv3(method:"GET", item:string(dir, "/advSearch_h.asp"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it's ProductCart, we should see an error message like:
  #   <font face="Arial" size=2>/productcart/pc/advSearch_h.asp</font><font face="Arial" size=2>, line 161</font>
  if (egrep(
    string:res, 
    pattern:">" + dir + "/advSearch_h\.asp<.+, line [0-9]+</font>")
   ) {
    # Try the exploit.
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/advSearch_h.asp?",
        "priceFrom=0&",
        "priceUntil=999999999&",
        # nb: this should just cause a syntax error.
        "idCategory='", SCRIPT_NAME, "&",
        "idSupplier=10&",
        "resultCnt=10&",
        "keyword=Nessus"
      ), 
      port:port
    );
    if (isnull(r)) exit(0);
    res = r[2];

    # If we get a syntax error in the query, there's a problem.
    if (string("Syntax error in string in query expression 'idCategory='", SCRIPT_NAME, "'") >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
