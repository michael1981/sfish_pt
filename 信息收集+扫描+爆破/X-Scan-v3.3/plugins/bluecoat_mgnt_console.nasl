#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#  thanks to the help of rd
#


include("compat.inc");

if(description)
{
 script_id(16363);
 script_version("$Revision: 1.5 $");
 
 script_name(english:"BlueCoat ProxySG Console Management Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a firewall." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a BlueCoat ProxySG appliance, an
enterprise-class firewall, and it allows connections to its web
console management application. 

Letting attackers know the type of firewall in use may help them focus
their attacks against the networks it protects." );
 script_set_attribute(attribute:"see_also", value:"http://www.bluecoat.com/products/sg" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
 script_summary(english:"Checks for BlueCoat web console management");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"Firewalls");
 script_dependencie("http_version.nasl");

 script_require_ports(8082);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

function https_get(port, request)
{
    local_var result, soc;

    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

port = 8082;
if(get_port_state(port))
{
  req = https_get(request:http_get(item:"/Secure/Local/console/logout.htm", port:port), port:port);
  if("<title>Blue Coat Systems  - Logout</title>" >< req)
  {
    security_note(port);
  }
}
