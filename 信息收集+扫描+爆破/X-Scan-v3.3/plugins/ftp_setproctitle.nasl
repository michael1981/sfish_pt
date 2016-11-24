#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11391);
 script_xref(name:"IAVA", value:"2000-b-0004");
 script_bugtraq_id(1425, 1438);
 script_cve_id("CVE-2000-0574");
 script_xref(name:"OSVDB", value:"7541");
 script_version ("$Revision: 1.13 $");

 script_name(english:"Multiple FTP Server setproctitle Function Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a remote command execution
attack." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server misuses the function setproctitle() and
may allow an attacker to gain a root shell on this host by 
logging in as 'anonymous' and providing a carefully crafted 
format string as its email address." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aee65ddc" );
 script_set_attribute(attribute:"solution", value:
"Install the latest patches from your vendor." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();


 script_summary(english:"Checks if the remote ftpd is vulnerable to format string attacks");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 banner = ftp_recv_line(socket:soc);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER anonymous\r\n"));
 r = ftp_recv_line(socket:soc);
 if(!egrep(pattern:"^331", string:r))exit(0);
 send(socket:soc, data:string("PASS %n%n%n%n%n%n%n\r\n"));
 r = ftp_recv_line(socket:soc);
 if(!r || !egrep(pattern:"^230",  string:r))exit(0);
 send(socket:soc, data:string("HELP\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)security_warning(port);
}
