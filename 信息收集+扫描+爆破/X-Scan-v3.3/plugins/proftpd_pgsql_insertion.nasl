#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11768);
 script_bugtraq_id(7974);
 script_cve_id("CVE-2003-0500");
 script_xref(name:"OSVDB", value:"9507");
 script_version ("$Revision: 1.12 $");
 
 script_name(english:"PostgreSQL Authentication Module (mod_sql) for ProFTPD USER Name Variable SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to read or modify arbitrary files on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server is vulnerable to a SQL injection when it 
processes the USER command.

An attacker may exploit this flaw to log into the remote host as any 
user." );
 script_set_attribute(attribute:"solution", value:
"If the remote server is ProFTPd, upgrade to ProFTPD 1.2.10." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 script_summary(english:"Performs a SQL insertion");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

banner = get_ftp_banner(port:port);
if( ! banner || "ProFTPD" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

banner = ftp_recv_line(socket:soc);
if ( ! egrep(pattern:"^220.*proftp", string:banner, icase:TRUE) ) exit(0);

if(!banner)exit(0);
send(socket:soc, data:'USER "\r\n');
r = recv_line(socket:soc, length:4096);
if(!r)exit(0);
close(soc);



soc = open_sock_tcp(port);
if(!soc)exit(0);
# The following causes a syntax error and makes the FTP
# daemon close the session
banner = ftp_recv_line(socket:soc);
if(!banner)exit(0);
send(socket:soc, data:string("USER '\r\n"));
r = recv_line(socket:soc, length:4096);
if(!r)
{
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
close(soc);
