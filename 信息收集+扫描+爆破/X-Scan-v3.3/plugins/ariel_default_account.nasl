#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(22870);
 script_version ("$Revision: 1.5 $");

 script_name(english:"Ariel FTP Server Default 'document' Account");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server can be accessed with a known login and password
pair." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Ariel FTP server. 

Ariel is a document transmission system mostly used in the academic
world. 

It is possible to log into the remote FTP server by connecting as the
user 'document' (or 'ariel4') and with a hex-encoded password based on
the IP address of the host the user is connecting from. 

An attacker could log into it and obtain the files from the print
queue or use the remote storage space for anything else." );
 script_set_attribute(attribute:"see_also", value:"http://www4.infotrieve.com/products_services/ariel.asp" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );


script_end_attributes();

 
 script_summary(english:"Checks if it is possible to log into the remote FTP server as the 'document' user");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_dependencie("DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("byte_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/ftp");
if ( ! port ) port = 419;
if ( ! get_port_state(port) ) exit(0);
if ( get_kb_item("ftp/" + port + "/AnyUser") ) exit(0);

banner = get_ftp_banner(port:port);
if ( banner !~ "^220 FTP ready\." ) exit(0);


soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

if ( ftp_authenticate(socket:soc, user:rand_str(length:8), pass:rand_str(length:8) ) )  exit(0);

close(soc);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

ip = split(this_host(), sep:'.', keep:FALSE);
for ( i = 0 ; i < 4 ; i ++ )
 pass += hexstr(mkbyte(int(ip[i])));

user = 'document';
pass = str_replace(string:toupper(pass), find:"0", replace:"#");

if ( ! ftp_authenticate(socket:soc, user:'document', pass:pass) ) 
{
 user = 'ariel4';
 close(soc);
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 if ( ! ftp_authenticate(socket:soc, user:'ariel4', pass:pass) )  exit(0);
}

port2 = ftp_pasv(socket:soc);
if ( ! port2 ) exit(0);

soc2 = open_sock_tcp(port2);
if (! soc2 ) exit(0);



send(socket:soc, data:'LIST\r\n');
buf = recv(socket:soc, length:4096);
listing = ftp_recv_listing(socket:soc2);
close(soc2);
close(soc);

report = 'It was possible to log in as \'' + user + '\'/\''+pass+'\'\n' + 'The output of the root directory is :\n\n' + listing;

security_warning(port:port, extra:report);




