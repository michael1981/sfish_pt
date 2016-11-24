#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18166);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1384");
  script_bugtraq_id(13433);
  script_xref(name:"OSVDB", value:"16353");
  script_xref(name:"OSVDB", value:"16354");

  script_name(english:"phpCOIN <= 1.2.2 Multiple SQL Injection Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
several SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpCOIN version 1.2.2 or older.  These
versions suffer from several SQL injection vulnerabilities due to
their failure to properly sanitize input to the 'search' parameter of
the 'index.php' script, the 'phpcoinsessid' parameter of the
'login.php' script and the 'id', 'dtopic_id', and 'dcat_id' parameters
of the 'mod.php' script before using it in SQL queries.  An attacker
may be able to exploit these flaws to alter database queries,
potentially revealing sensitive information or even modifying data." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0499.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.phpcoin.com/index.php?showtopic=4607" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_summary(english:"Checks for multiple SQL injection vulnerabilities in phpCOIN <= 1.2.2");

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


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through each directory with scripts.
foreach dir (cgi_dirs()) {

  # Try a couple of different ways to exploit the flaws.
  i = 0;
  # - POST request with SQL injection via 'id'.
  postdata = string(
    "mod=siteinfo&",
    "id=", SCRIPT_NAME, "'&",
    "phpcoinsessid=3ff9120788558adc3b6c8352d808c861"
  );
  exploits[i++] = http_mk_post_req(item: dir+"/mod.php", port: port, version: 11,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data: postdata );
  # - same as above but a GET request.
  exploits[i++] = http_mk_get_req(item:string(dir, "/mod.php?", postdata), port:port);
  # - POST request with SQL injection via session id.
  postdata = string(
    "w=user&",
    "o=login&",
    "phpcoinsessid=", SCRIPT_NAME, "'"
  );
  exploits[i++] = http_mk_post_req(item: dir + "/login.php", version: 11, 
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data: postdata);
  # - same as above but a GET request.
  exploits[i++] = http_mk_get_req(item:string(dir, "/login.php?", postdata), port:port);

  foreach exploit (exploits) {
    r = http_send_recv_req(port:port, req: exploit);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # It's a problem if we see an error with our script name followed
    # by a single quote. This error message is hardcoded into 
    # db_query_execute() in coin_database/db_mysql.php.
    if (egrep(pattern:string("Unable to execute query: .+='", SCRIPT_NAME, "''"), string:res)) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
