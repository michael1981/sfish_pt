#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19515);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2736", "CVE-2005-4799", "CVE-2006-4421");
  script_bugtraq_id(14670, 15092, 15095, 19709, 23814);
  script_xref(name:"OSVDB", value:"19016");
  script_xref(name:"OSVDB", value:"19958");
  script_xref(name:"OSVDB", value:"19959");
  script_xref(name:"OSVDB", value:"29298");

  script_name(english:"YaPiG <= 0.9.5b Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
code injection and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running YaPiG, a web-based image gallery written in
PHP. 

According to its banner, the version of YaPiG installed on the remote
host is prone to arbitrary PHP code injection and cross-site scripting
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://cedri.cc/advisories/EXIF_XSS.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.seclab.tuwien.ac.at/advisories/TUVSA-0510-001.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-08/0483.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in YaPiG <= 0.9.5b";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Pull up the main page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (isnull(res)) exit(0);

  # Check the version number of YaPiG.
  if (
    egrep(
      string:res, 
      pattern:"Powered by <a href=.+>YaPiG.* V0\.([0-8][0-9]($|[^0-9])|9([0-4]|5[.ab]))"
    )
  ) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
