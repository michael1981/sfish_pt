#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(18219);
 script_version("$Revision: 1.4 $");
 
 script_name(english:"Clearswift MIMEsweeper Manager Console Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web and e-mail gateway security 
application." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running MIMEsweeper for SMTP, 
connections  are allowed to the web MIMEsweeper manager console.

Letting attackers know that you are using this software will help them 
to focus their attack or will make them change their strategy." );
 script_set_attribute(attribute:"see_also", value:"http://www.clearswift.com/" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

script_end_attributes();

 
 summary["english"] = "Checks for MIMEsweeper manager console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#da code now

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_port_state(port))
{
 req = http_get(item:"/MSWSMTP/Common/Authentication/Logon.aspx", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>MIMEsweeper Manager</title>" >< rep)
 {
	security_note(port);
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
exit(0);
