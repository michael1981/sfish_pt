#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

include("compat.inc");

if(description)
{
 script_id(17282);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "vBulletin Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a bulletin board system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running vBulletin, a commercial web-based message
forum application written in PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.vbulletin.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 
 summary["english"] = "Checks for the presence of vBulletin";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d (list_uniq(make_list("/forum", cgi_dirs())))
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 res = egrep(pattern:" content=.vBulletin ", string:res, icase:TRUE);
 if( res )
 {
  if (d == "") d = "/";
  vers = ereg_replace(pattern:".*vBulletin ([0-9.]+).*", string:res, replace:"\1", icase:TRUE);
  set_kb_item(name:string("www/", port, "/vBulletin"),
  	      value:string(vers," under ",d));

  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote host is running vBulletin " + vers + " under " + d + "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);     
 }
} 
