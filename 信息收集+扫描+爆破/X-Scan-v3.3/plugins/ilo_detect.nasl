#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#
#
# Modifications by Tenable :
#
# - Description
# - Family change (1/21/2009)
#
# Modifications by Daniel Reich <me at danielreich dot com>
#
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the 
#   order of Copyright and &copy;
# - Revision 1.2
#


include("compat.inc");

if(description)
{
script_id(20285);

script_version("$Revision: 1.6 $");
script_name(english:"HP Integrated Lights-Out Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is an HP Integrated Lights-Out console." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP Integrated Lights Out (iLO), a remote
server management software that is integrated into HP ProLiant
servers." );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port if you do not use it" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

script_summary(english:"Detects iLO");

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"Service detection");
 script_require_ports("Services/www", 80);
 script_dependencies("httpver.nasl");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);

buf = http_get(item:"/login.htm", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(
  ("<TITLE>HP Integrated Lights-Out Login<" >< r &&
  egrep(pattern:"Copyright .+ Hewlett-Packard Development Company", string:r)) ||
  ("<title>HP Remote Insight<" >< r &&
  egrep(pattern:"Hewlett-Packard Development Company", string:r) )

) 
     {
      set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
      security_note(port);
     }
  
