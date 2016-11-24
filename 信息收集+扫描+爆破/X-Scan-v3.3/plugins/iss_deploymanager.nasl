#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, family change (9/1/09)


include("compat.inc");

if(description)
{
 script_id(17585);
 script_version("$Revision: 1.5 $");
 
 script_name(english:"ISS Deployment Manager Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a deployment manager for a security 
application." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to run ISS deployment manager. Connections are 
allowed to the web interface to remote install various SiteProtector 
components.

Letting attackers know that you are using this software will help them 
to focus their attack or will make them change their strategy.

In addition to this, an attacker may attempt to set up a brute force attack
to log into the remote interface." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 script_summary(english:"Checks for ISS deployment manager web interface");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"Service detection");
 script_dependencie("http_version.nasl");
 script_require_ports(3994);
 exit(0);
}

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

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 3994;
if(get_port_state(port))
{
 req = http_get(item:"/deploymentmanager/index.jsp", port:port);
 rep = https_get(request:req, port:port);
 if( rep == NULL ) exit(0);

if ("<title>SiteProtector</title>" >< rep && egrep(pattern:"Welcome to SiteProtector Deployment Manager", string:rep))
 {
    security_note(port);
 }
}
