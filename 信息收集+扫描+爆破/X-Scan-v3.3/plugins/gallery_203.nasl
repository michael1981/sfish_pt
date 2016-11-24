#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21017);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2006-1127", "CVE-2006-1128");
  script_bugtraq_id(16940, 16948);
  script_xref(name:"OSVDB", value:"23596");
  script_xref(name:"OSVDB", value:"23597");

  script_name(english:"Gallery < 2.0.3 Multiple Remote Vulnerabilities (XSS, Traversal)");
  script_summary(english:"Checks for IP spoofing in Gallery");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gallery, a web-based photo album
application written in PHP. 

The version of Gallery installed on the remote host allows an attacker
to spoof his IP address with a bogus 'X_FORWARDED_FOR' HTTP header. 
An authenticated attacker can reportedly leverage this flaw to launch
cross-site scripting attacks by adding comments to a photo as well as
other attacks. 

In addition, the application reportedly fails to validate a session id
before using it, which can be used to delete arbitrary files on the
remote host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00106-03022006" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426655/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/gallery_2.0.3_released" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 2.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

init_cookiejar();
foreach dir (dirs) {
  ip = string("nessus", rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789"));
  useragent = string("Mozilla/4.0 (compatible; ", SCRIPT_NAME, "; Googlebot)");

  r = http_send_recv3(method: 'GET', item:string(dir, "/main.php"), port:port,
    add_headers: make_array( "X_FORWARDED_FOR", ip, 
    		 	     "User-Agent", useragent) );
  if (isnull(r)) exit(0);

  # There's a problem if the GALLERYSID cookie has our fake "IP".
  val = get_http_cookie(name: "GALLERYSID");
  if (egrep(pattern:string("google", ip), string: val)) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
