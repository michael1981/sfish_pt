#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25811);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-4053");
  script_bugtraq_id(25119);
  script_xref(name:"OSVDB", value:"36286");

  script_name(english:"LinPHA include/img_view.class.php order parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LinPHA, a web photo gallery application
written in PHP. 

The version of LinPHA installed on the remote host fails to sanitize
input to the 'order' parameter of the 'new_images.php' script before
using it in the 'setSql' function in 'include/img_view.class.php' in a
database query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker may be able to exploit this issue to
manipulate such queries, leading to disclosure of sensitive
information, modification of data, or attacks against the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4242" );
 script_set_attribute(attribute:"see_also", value:"http://linpha.cvs.sourceforge.net/linpha/linpha/ChangeLog?revision=1.1264" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LinPHA 1.3.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/linpha", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  exploit = string(SCRIPT_NAME, "_", unixtime());
  req = http_get(
    item:string(
      dir, "/new_images.php?",
      "order=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # If it looks like the exploit worked...
  if (
    "Unknown table" >< res ||
    egrep(pattern:string("ORDER by .+\\.", exploit), string:res)
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
