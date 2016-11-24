#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14699);
 script_bugtraq_id(11131);
 script_xref(name:"OSVDB", value:"9433");
 script_version("$Revision: 1.5 $");

 script_name(english:"TYPSoft FTP Server Crafted RETR Command Sequence Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running TYPSoft FTP 1.11 or 
earlier. TYPSoft FTP Server is prone to a remote denial of 
service vulnerability that may allow an attacker to cause 
the server to crash by sending a malformed 'RETR' command 
to the remote server" );
 script_set_attribute(attribute:"solution", value:
"Use a different FTP server or upgrade to the newest 
version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for version of TYPSoft FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if( ! banner ) exit(0);
if(egrep(pattern:".*TYPSoft FTP Server (0\.|1\.[0-9][^0-9]|1\.1[01][^0-9])", string:banner) )
    security_warning(port);
