#
# (C) Tenable Network Security
#

# Ref:
#  Date: Thu, 05 Jun 2003 11:08:44 -0500
#  From: KF <dotslash@snosoft.com>
#  To: bugtraq@securityfocus.com
#  Subject: SRT2003-06-05-0935 - HPUX ftpd remote issue via REST 
#

include("compat.inc");

if(description)
{
 script_id(11701);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(7825);
 script_xref(name:"OSVDB", value:"51721");
 
 script_name(english:"HP-UX FTPD REST Command Remote Arbitrary Memory Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to disclose the contents of the memory of the remote host" );
 script_set_attribute(attribute:"description", value:
"The remote FTP server seems to be vulnerable to an integer conversion bug when 
it receives a malformed argument to the 'REST' command.

An attacker may exploit this flaw to force the remote FTP daemon to disclose portions
of the memory of the remote host." );
 script_set_attribute(attribute:"solution", value:
"If the remote FTP server is HP/UX ftpd, then apply patch PHNE_21936." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C" );
 script_end_attributes();

                    
 
 script_summary(english:"Checks if the remote ftp sanitizes the RETR command");
 script_category(ACT_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

banner = get_ftp_banner(port:port);
if(banner == NULL)exit(0);

# ProFTPD may seem vulnerable, but actually checks the REST argument
# at download time.
if("ProFTPD" >< banner || "Version wu-" >< banner)exit(0);

if ( " FTP server" >!< banner ) exit(0);

if ( "PHNE_31931" >< banner || "PHNE_30990" >< banner ) exit(0);

if( ! login ) { exit(0); }
soc = open_sock_tcp(port);
if(!soc)exit(0);

if( ftp_authenticate(socket:soc, user:login, pass:pass ) ) 
{
 send(socket:soc, data:'REST 1111111111111111\r\n');
 r = recv_line(socket:soc, length:4096);
 ftp_close(socket:soc);
 if("2147483647" >< r ) security_hole(port);
}
