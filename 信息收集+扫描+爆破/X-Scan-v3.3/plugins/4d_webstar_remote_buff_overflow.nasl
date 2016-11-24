#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Braden Thomas <bjthomas@usc.edu>
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(18212);
 script_version ("$Revision: 1.8 $");
 
 script_cve_id("CVE-2005-1507");
 script_bugtraq_id(13538, 14192);
 script_xref(name:"OSVDB", value:"16154");

 name["english"] = "4D WebSTAR Tomcat Plugin Remote Buffer Overflow";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a remote buffer overflow
attack." );
 script_set_attribute(attribute:"description", value:
"The remote server is running 4D WebSTAR Web Server. 

According to its banner, the remote version of 4D WebSTAR has a buffer
overflow in its Web Server Tomcat plugin, included and activated by
default.  By sending a malicious packet, an attacker may be able to
crash the affected service or possibly execute arbitrary code on the
affected host, although that appears to be improbable." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0086.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for 4D WebSTAR";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.|4[^.]))", string:banner) ) security_warning(port);
