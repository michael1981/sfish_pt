#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: @stake inc.
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Changed plugin family (8/31/09)


include("compat.inc");

if(description)
{
 script_id(14241);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0698");
 script_bugtraq_id(10714);
 script_xref(name:"OSVDB", value:"7797");
 script_xref(name:"Secunia", value:"12063");

 script_name(english:"4D WebSTAR Symlink Privilege Escalation");
 script_summary(english:"Checks for 4D FTP Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a local symbolic link
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running 4D WebStar FTP Server. The version of 4D
WebStar FTP Server on the remote host is reportedly affected by a
local symbolic link vulnerability caused by the application opening
files without properly verifying their existence or their absolute
location.

Successful exploitation of this issue will allow an attacker to write
to arbitrary files subject to the permissions of the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2004-q3/0005.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 4D WebStar 5.3.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"FTP");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80, "Services/ftp", 21);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) 
	exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 port = get_kb_item("Services/ftp");
 if ( ! port ) 
	port = 21;
 if ( ! get_port_state(port) ) 
	exit(0);
 ftpbanner = get_ftp_banner(port:port);
 if ( egrep(string:ftpbanner, pattern:"^220 FTP server ready\."))
 { 
  security_note(port);
 }
}
