#
# This script was written by Orlando Padilla <orlando.padilla@digitaldefense.net>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if (description)
{
    script_id(11204);
    script_version("$Revision: 1.19 $");

    script_xref(name:"OSVDB", value:"872"); 

    script_name(english:"Apache Tomcat Default Accounts");
    script_summary(english:"Apache Tomcat Default Accounts");

    script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that can be accessed with
default credentials." );
    script_set_attribute(attribute:"description", value:
"This host appears to be the running the Apache Tomcat
Servlet engine with the default accounts still configured.
A potential intruder could reconfigure this service in a way
that grants system access." );
    script_set_attribute(attribute:"solution", value:
"Change the default passwords by editing the 
admin-users.xml file located in the /conf/users
subdirectory of the Tomcat installation." );
    script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
    script_end_attributes();

    script_category(ACT_ATTACK);

    script_copyright( english:"This script is Copyright (C) 2003-2009 Digital Defense Inc.");

    family["english"] = "Web Servers";

    script_family(english:family["english"]);
    script_dependencie("find_service1.nasl", "http_version.nasl");
    script_require_ports("Services/www");
    exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:8080);
if ( ! port ) exit(0);

if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (banner && "Tomcat" >!< banner && "Coyote" >!< banner) exit(0);
}

#assert on init
flag=1;

#list of default acnts base64()'d
auth[0]=string("YWRtaW46dG9tY2F0\r\n\r\n");     real_auth[0]=string("admin:tomcat");
auth[1]=string("YWRtaW46YWRtaW4=\r\n\r\n");     real_auth[1]=string("admin:admin");
auth[2]=string("dG9tY2F0OnRvbWNhdA==\r\n\r\n"); real_auth[2]=string("tomcat:tomcat");
auth[3]=string("cm9vdDpyb290\r\n\r\n");         real_auth[3]=string("root:root");
auth[4]=string("cm9sZTE6cm9sZTE=\r\n\r\n");     real_auth[4]=string("role1:role1");
auth[5]=string("cm9sZTpjaGFuZ2V0aGlz\r\n\r\n"); real_auth[5]=string("role:changethis");
auth[6]=string("cm9vdDpjaGFuZ2V0aGlz\r\n\r\n"); real_auth[6]=string("root:changethis");
auth[7]=string("dG9tY2F0OmNoYW5nZXRoaXM=\r\n\r\n");     real_auth[7]=string("tomcat:changethis");
auth[8]=string("eGFtcHA6eGFtcHA=\r\n\r\n");     real_auth[8]=string("xampp:xampp");
auth[9]=string("YWRtaW46Y2hhbmdldGhpcw==\r\n\r\n");     real_auth[9]=string("admin:changethis");


#basereq string
basereq = http_get(item:"/admin/contextAdmin/contextList.jsp", port:port);
basereq = basereq - string("\r\n\r\n");

authBasic=string("\r\n","Authorization: Basic ");

i = 0;
found = 0;
report = string("\n");

if(get_port_state(port))
{
	if(http_is_dead(port:port))exit(0);
	
	# Check that we need any authorization at all
	soc = http_open_socket(port);
	if(!soc)exit(0);
	send(socket:soc, data:http_get(item:"/admin/contextAdmin/contextList.jsp", port:port));
	rs = http_recv(socket:soc);
	
	http_close_socket(soc);
	if(!ereg(pattern:"^HTTP/1\.[0-1] 401 ", string:rs))exit(0);
	if(("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs))exit(0);
	
	
	while( auth[i] )
	{
	 soc = http_open_socket(port);
	 if(soc)
	 {
	   t0 = string(basereq,authBasic,auth[i]);
	   send(socket:soc,data:t0);
	   rs = http_recv(socket:soc);

           if (!isnull(rs) && !egrep(pattern:"Context (list|Admin)",string:rs))
           {
	     basereq = http_get(item:"/admin/contextAdmin/contextAdmin.html", port:port);
	     basereq = basereq - string("\r\n\r\n");
	     t0 = string(basereq,authBasic,auth[i]);
	     send(socket:soc,data:t0);
	     rs = http_recv(socket:soc);
           }  
            
       	   # minor changes between versions of jakarta
	   if(!isnull(rs) && (("<title>Context list</title>" >< rs) || ("<title>Context Admin</title>" >< rs) || "<title>Admin Context</title>" >< rs))
	   { 
		found = found + 1;
		if(found == 1)
			report = string("\nThe following accounts were discovered: \n\n",real_auth[i], "\n");
		else {
			report = string(report, string(real_auth[i], "\n"));
		}
	   }
	   http_close_socket(soc);
	   i=i+1;	   
	  }
	}
}

# should we include the plugin description?
if (found)
{
 security_hole(port:port,extra:report);
}
