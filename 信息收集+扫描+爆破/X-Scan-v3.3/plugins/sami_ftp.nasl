#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12061);
 script_cve_id("CVE-2004-2081", "CVE-2004-2082");
 script_bugtraq_id(9657);
 script_xref(name:"OSVDB", value:"3961");
 script_xref(name:"OSVDB", value:"45192");
 script_version ("$Revision: 1.12 $");

 script_name(english:"Sami FTP Server Multiple DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to multiple denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SAMI FTP server. 

There is a bug in the way this server handles certain FTP command
requests that may allow an attacker to crash the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-02/0382.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();


 script_summary(english:"SAMI Remote DoS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_require_ports("Services/ftp", 21);
 script_dependencie("find_service1.nasl", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

# ok, so here's what it looks like:
#220-Sami FTP Server
#220-
#220 Features p a .
#User (f00dikator:(none)): anonymous
#230 Access allowed.
#ftp> cd ~
#Connection closed by remote host.

if( "Sami FTP Server" >< banner ) {
    if (safe_checks() == 0) { 
        req1 = string("USER anonymous\r\n");
        req2 = string("CWD ~\r\n");
        # SAMI ftp, when anonymous enabled, requires no password.... 
        soc=open_sock_tcp(port);
 	if ( ! soc ) exit(0);
        send(socket:soc, data:req1);    
        r = ftp_recv_line(socket:soc);
        if ( "Access allowed" >< r ) {
            send(socket:soc, data:req2 );
            r = recv_line(socket:soc, length:64, timeout:3);
	    close(soc);
            if (!r) security_warning(port);
        }
    } else {
        security_warning(port);
    }
}
