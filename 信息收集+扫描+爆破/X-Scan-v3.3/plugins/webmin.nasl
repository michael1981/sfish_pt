#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/13/2009)

include("compat.inc");

if(description)
{
 script_id(10757);
 script_version ("$Revision: 1.20 $");

 script_name(english:"Webmin Detection");
 script_set_attribute(attribute:"synopsis", value:
"An administration service is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote server is running Webmin, a web-based interface for system
administration for Unix." );
 script_set_attribute(attribute:"see_also", value:"http://www.webmin.net/" );
 script_set_attribute(attribute:"solution", value:
"Stop the Webmin service if not needed or ensure access is limited to
authorized hosts.  See the menu items '[Webmin Configuration][IP
Access Control]' and/or '[Webmin Configuration][Port and Address]'." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english:"Check for Webmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Alert4Web.com");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 10000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:10000);

foreach port (ports)
{
 banner = get_http_banner(port:port);

 if(banner)
 {
  if(egrep(pattern:"^Server: MiniServ.*",string:banner))
  {
     banner = http_keepalive_send_recv(port:port, data:http_get(item:"/",port:port), embedded:TRUE);
     if(banner != NULL ) {
     if(egrep(pattern:"webmin", string:banner, icase:TRUE))
     {
     set_kb_item(name:"Services/www/webmin", value:port);
     set_kb_item(name:"www/" + port + "/webmin", value:TRUE);

     version = ereg_replace(pattern:".*Webmin *([0-9]\.[0-9][0-9]).*$",
    			    string:banner,
			    replace:"\1");
     if (version == banner) version = 0;
     if (version)
     {
      report = string ("\nThe Webmin version is : ", version, "\n");

      security_note(port:port, extra:report);
      set_kb_item(name:"webmin/" + port + "/version",value:version); 
     }
     else
       security_note(port);
    }
   }
  }
 }
}
