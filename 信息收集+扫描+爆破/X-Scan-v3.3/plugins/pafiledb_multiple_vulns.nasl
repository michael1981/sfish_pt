#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17329);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2004-1219", "CVE-2004-1551", "CVE-2004-1975", "CVE-2005-0326",
    "CVE-2005-0327", "CVE-2005-0723", "CVE-2005-0724", "CVE-2005-0781", "CVE-2005-0782");
  script_bugtraq_id(7183, 8271, 10229, 11817, 11818, 12758, 12788, 13967);
  script_xref(name:"OSVDB", value:"5695");
  script_xref(name:"OSVDB", value:"5695");
  script_xref(name:"OSVDB", value:"14685");
  script_xref(name:"OSVDB", value:"14686");
  script_xref(name:"OSVDB", value:"14687");
  script_xref(name:"OSVDB", value:"14688");
  script_xref(name:"OSVDB", value:"14839");
  script_xref(name:"OSVDB", value:"14840");
  script_xref(name:"OSVDB", value:"14841");
  script_xref(name:"OSVDB", value:"14842");
 
  script_name(english:"paFileDB <= 3.1 Multiple Vulnerabilities (2)");
  script_summary(english:"Checks for multiple vulnerabilities in paFileDB 3.1 and Older");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of paFileDB that is prone to a
wide variety of vulnerabilities, including arbitrary file uploads,
local file inclusion, SQL injection, and cross-site scripting issues." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try various SQL injection attacks.
  exploits = make_list(
    "/pafiledb.php?action=viewall&start='&sortby=rating",
    "/pafiledb.php?action=category&start='&sortby=rating"
  );
  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # It's a problem if MySQL encountered a syntax error.
    if (egrep(string:res, pattern:"MySQL Returned this error.+ error in your SQL syntax")) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
