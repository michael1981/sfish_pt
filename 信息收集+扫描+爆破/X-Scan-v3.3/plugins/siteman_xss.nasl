#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16171);
  script_version("$Revision: 1.8 $");
  
  script_bugtraq_id(12267);
  script_xref(name:"OSVDB", value:"12985");

  script_name(english:"Siteman forum.php page Parameter XSS");
  script_summary(english:"Checks Siteman XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by\n",
      "a cross-site scripting attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Siteman, a web-based content management\n",
      "system written in PHP.\n",
      "\n",
      "The remote version of this software is vulnerable to a cross-site\n",
      "scripting attack due to a lack of sanitization of user-supplied data\n",
      "to the 'page' parameter of the 'forum.php' script.  Successful\n",
      "exploitation of this issue may allow an attacker to use the remote\n",
      "server to perform an attack against a third-party user."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0162.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir (cgi_dirs())
{
 buf = http_get(item:dir + "/forum.php?do=viewtopic&cat=1&topic=1&page=1?<script>foo</script", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if(isnull(r))exit(0);

 if(egrep(pattern:"a class=.cal_head. href=.*<script>foo</script>", string:r))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
