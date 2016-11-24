#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#
# - modified by Josh Zlatin-Amishav to support newer versions of the product.


include("compat.inc");

if(description)
{
 script_id(15615);
 script_version("$Revision: 1.8 $");
 
 script_name(english:"McAfee IntruShield Management Console Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running McAfee IntruShield Management Console." );
 script_set_attribute(attribute:"description", value:
"If an attacker can log into the IntruShield Management Console on the
remote host, he will have the ability to modify sensors configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/mcafee/network_ips/category.htm" );
 script_set_attribute(attribute:"solution", value:
"Configure your firewall to prevent unauthorized hosts from
connecting to this port" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
 summary["english"] = "Detect McAfee IntruShield Management Console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Service detection");

 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

req = http_get(item:"/intruvert/jsp/admin/Login.jsp", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( r == NULL )exit(0);
if (
  egrep(pattern:"Copyright \(c\) 2001.* (Intruvert Network Inc|Networks Associates Technology)", string:r) &&
  egrep(pattern:"<(title|TITLE)>IntruShield Login", string:r)
) security_note(port);
