#
# (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(11652);
 script_version ("$Revision: 1.10 $");
 
 script_name(english:"Mantis Detection");
 script_summary(english:"Checks for the presence of Mantis");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bug tracking application written in
PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mantis, an open-source bug tracking
application written in PHP and with a MySQL back-end." );
 script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


# Search for Mantis.
if (thorough_tests) dirs = list_uniq(make_list("/bugs", "/mantis", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/login_page.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( res == NULL ) exit(0);

  res = egrep(pattern:"(http://mantisbt\.sourceforge\.net|http://www\.mantisbt\.org).*Mantis [0-9]", string:res, icase:TRUE);
  if( res ) {
    ver = ereg_replace(pattern:".*Mantis ([0-9][^ <]*).*", string:res, replace:"\1", icase:TRUE);
    if (dir == "") dir = "/";

    set_kb_item(
      name:string("www/", port, "/mantis"),
      value:string(ver, " under ", dir)
    );
	      
    info = string("Mantis ", ver, " was detected on the remote host under\nthe path ", dir, ".");
    security_note(port:port, extra:'\n'+info);

    exit(0);     
  }
} 
