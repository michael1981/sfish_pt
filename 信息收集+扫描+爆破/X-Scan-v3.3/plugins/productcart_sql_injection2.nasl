#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18436);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1967", "CVE-2005-2445");
  script_bugtraq_id(13881);
  script_xref(name:"OSVDB", value:"17329");
  script_xref(name:"OSVDB", value:"17330");

  script_name(english:"ProductCart Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
multiple SQL injection issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ProductCart shopping cart
software that fails to properly sanitize user-supplied input before
using it in SQL queries.  An attacker may be able to exploit these
flaws to alter database queries, disclose sensitive information, or
conduct other such attacks.  Possible attack vectors include the
'idcategory' parameter of the 'viewPrd.asp' script, the 'lid'
parameter of the 'editCategories.asp' script, the 'idc' parameter of
the 'modCustomCardPaymentOpt.asp' script, and the 'idccr' parameter of
the 'OptionFieldsEdit.asp' script." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-07/0521.html" );
 script_set_attribute(attribute:"see_also", value:"http://echo.or.id/adv/adv16-theday-2005.txt" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  summary["english"] = "Checks for multiple SQL injection vulnerabilities (2) in ProductCart";
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
  # nb: the exploit requires a valid product id.

  # Try to pull up ProductCart's list of categories.
  r = http_send_recv3(method:"GET", item:string(dir, "/viewCat.asp"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like ProductCart...
  if (res =~ "<a href=viewCat.asp>.+Our Products</a>") {
    # Get category ids.
    ncats = 0;
    pat = "href='viewCat_h.asp?idCategory=([0-9]+)'>";
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cat = eregmatch(pattern:pat, string:match);
        if (!isnull(cat)) cats[ncats++] = cat[1];
      }
    }

    # Get product ids for a given category.
    for (i=0; i< ncats; i++) {
      cat = cats[i];

      r = http_send_recv3(method:"GET", item:string(dir, "/viewCat_h.asp?idCategory=", cat), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      pat = string("href='viewPrd.asp?idcategory=", cat, "&idproduct=([0-9]+)'>");
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      if (matches) {
        foreach match (split(matches)) {
          match = chomp(match);
          prod = eregmatch(pattern:pat, string:match);
          if (!isnull(prod)) {
            prod = prod[1];
            # nb: we only need to find 1 valid product id.      
            break;
          }
        }
      }

      # If we have a product id, try to exploit the flaw.
      if (prod) {
        r = http_send_recv3(method:"GET",
          item:string(
            dir, "/viewPrd.asp?",
            "idcategory=", cat, "'&",
            "idproduct=", prod
          ), 
          port:port
        );
        if (isnull(r)) exit(0);
	res = r[2];

        # There's a problem if we see a syntax error.
        if (egrep(string:res, pattern:string("Syntax error.+'idcategory=", cat), icase:TRUE)) {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }

        # We're not vulnerable, but we're finished checking this dir.
        break;
      }
    }
  }
}
