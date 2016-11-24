#
# Bofra virus detection
#
# Author: Brian Smith-Sweeney (brian@smithsweeney.com)
# http://www.smithsweeney.com
#
# Created: 11/15/04
# Last Updated: 11/15/04
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
        script_id(15746);
        script_version ("$Revision: 1.9 $");
	script_cve_id("CVE-2004-1050");
	script_bugtraq_id(11515);
	script_xref(name:"OSVDB", value:"11337");
        script_name(english:"Microsoft IE FRAME/IFRAME/EMBED Tag Overflow (Bofra Worm Detection)");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected with a worm." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to have been infected with the Bofra worm or one of its 
variants, which infects machines via an Internet Explorer IFRAME exploit.  
It is very likely this system has been compromised." );
 script_set_attribute(attribute:"solution", value:
"Verify that the remote system has been compromised, and re-install
if necessary." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/security_response/writeup.jsp?docid=2004-111113-3948-99" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 
        summary["english"] = "Determines the presence of a Bofra worm infection resulting from an IFRAME exploit";
        family["english"] = "Backdoors";
script_end_attributes();

        script_summary(english:summary["english"]);
        script_category(ACT_GATHER_INFO);
        script_copyright(english:"This script is Copyright (C) 2004-2009 Brian Smith-Sweeney");
        script_family(english:family["english"]);
	script_dependencies('http_version.nasl');
	script_require_ports(1639);
        exit(0);
}
 
#
# User-defined variables
#
# This is where we saw Bofra; YMMV
port=1639;

#
# End user-defined variables; you should not have to touch anything below this
#

# Get the appropriate http functions
include("http_func.inc");
include("http_keepalive.inc");


if ( ! get_port_state ( port ) ) exit(0);

# Prep & send the http get request, quit if you get no answer
req = http_get(item:"/reactor",port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
hex_res=hexstr(res);
if ("3c0049004600520041004d00450020005300520043003d00660069006c0065003a002f002f00" >< hex_res )
	security_hole(port);
else {
	if (egrep(pattern:"<IFRAME SRC=file://",string:res)){
		security_hole(port);
	}
}
