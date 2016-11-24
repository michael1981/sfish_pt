#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Output formatting, family change (8/22/09)

include("compat.inc");

if(description)
{
 script_id(10820);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-1999-0508");

 script_name(english:"F5 Device Default Support Password");
 script_summary(english:"F5 Device Default Support Password");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default administrative
credentials.");
 script_set_attribute(attribute:"description", value:
"The remote F5 Networks device has the default password set for the
'support' user account.  This account normally provides read/write
access to the web configuration utility.  An attacker could take
advantage of this to reconfigure your systems and possibly gain shell
access to the system with super-user privileges.");
 script_set_attribute(attribute:"solution", value:
"Remove the 'support' account entirely or change the password of this
account to something that is difficult to guess.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2001/12/06");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Digital Defense Inc.");
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:443);
if (  !port ) exit(0);
soc = http_open_socket(port);
if (soc)
 {
    req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if (!isnull(buf) && ("/bigipgui/" >< buf) && ("System Command" >< buf))
    {
     security_hole(port);
     set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
    }
 }
