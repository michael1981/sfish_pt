#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11565);
 script_version ("$Revision: 1.12 $");
 script_name(english:"FTP Server root Directory .forward File Present");
 script_summary(english:"Downloads the remote .forward file");

 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote anonymous FTP server has a .forward file set in its home.
An attacker may use it to determine who is in charge of the FTP server
and set up a social engineering attack." );
 script_set_attribute(attribute:"solution", value:
"Remove the .forward file." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor') || 
    get_kb_item('ftp/'+port+'/broken')) exit(0);

if(! get_port_state(port)) exit(0);

login = "anonymous";
password = "nessus@nessus.org";

# if(! login) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

if(! ftp_authenticate(socket:soc, user:login,pass:password))
{
 ftp_close(socket: soc); exit(0);
}

send(socket:soc, data: 'CWD\r\n');
a = ftp_recv_line(socket:soc);
pasv = ftp_pasv(socket:soc);
if (! pasv) { ftp_close(socket: soc); exit(0); }
 
soc2 = open_sock_tcp(pasv);
send(socket:soc, data: 'RETR .forward\r\n');
r = ftp_recv_line(socket:soc);

if(egrep(pattern:"^(425|150) ", string:r))
{
   r = ftp_recv_data(socket:soc2, line:r);
   close(soc2);
   if ( strlen(r) == 0 )
   {
    r2 = ftp_recv_line(socket:soc);
    if ( r2[0] == '5' ) exit(0);
   } 
report = "The .forward file contains : " + '\n' + r + '\n';

   security_warning(port:port, extra:report);
}

ftp_close(socket:soc);

