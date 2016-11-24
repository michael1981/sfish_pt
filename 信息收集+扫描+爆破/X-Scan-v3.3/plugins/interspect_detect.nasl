#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, fixed description, changed family (1/21/2009)


include("compat.inc");

if(description)
{
 script_id(15614);
 script_version("$Revision: 1.7 $");
 
 script_name(english:"Check Point InterSpect Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an internet security gateway." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Check Point InterSpect,
an internet security gateway. 

The Nessus host is likely to have been put in quarantine, 
its activity will be dropped for 30 minutes by default." );
 script_set_attribute(attribute:"see_also", value:"http://www.checkpoint.com" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

script_end_attributes();

 
 script_summary(english:"Detect Check Point InterSpect");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Service detection");
 script_dependencie("httpver.nasl");
 script_require_ports(80,3128);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

r = http_get_cache(item:"/", port:port);
if( r == NULL )exit(0);
if (egrep(pattern:"<TITLE>Check Point InterSpect - Quarantine</TITLE>.*Check Point InterSpect", string:r))
   {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
   }
