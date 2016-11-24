#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18621);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-2156");
  script_bugtraq_id(14133);
  script_xref(name:"OSVDB", value:"17712");

  script_name(english:"PHPNews news.php prevnext Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPNews, an open-source news application
written in PHP. 

The installed version of PHPNews is prone to a SQL injection attack
due to its failure to sanitize user-supplied input via the 'prevnext'
parameter of the 'news.php' script.  An attacker can exploit this flaw
to affect database queries, possibly revealing sensitive information,
launching attacks against the underlying database, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://newsphp.sourceforge.net/changelog/changelog_1.26.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPNews 1.2.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for prevnext parameter SQL injection vulnerability in PHPNews";
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpnews", "/news", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  r = http_send_recv3(method:"GET", port: port, 
    item:string(
      dir, "/news.php?",
      "prevnext=1'", SCRIPT_NAME));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it looks like a MySQL error.
  if ("mysql_fetch_assoc(): supplied argument is not a valid MySQL result" >< res){
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
