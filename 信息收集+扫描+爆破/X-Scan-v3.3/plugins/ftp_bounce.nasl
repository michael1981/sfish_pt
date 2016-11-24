#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10081);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0017");
 script_bugtraq_id(126);
 script_xref(name:"OSVDB", value:"71");
 script_name(english:"FTP Privileged Port Bounce Scan");
 script_summary(english:"Checks if the remote ftp server can be bounced");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to a FTP server bounce attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to force the remote FTP server to connect to third
parties using the PORT command. 

The problem allows intruders to use your network resources to scan
other hosts, making them think the attack comes from your network." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1995_3/0047.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-10/0367.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-1997-27.html");

 script_set_attribute(attribute:"solution", value:
"See the CERT advisory in the references for solutions and workarounds ." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_family(english:"FTP"); 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "ftp_kibuv_worm.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("ftp/ncftpd");
 exit(0);
}

#
# The script code starts here :
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if (get_kb_item('ftp/'+port+'/backdoor') ||
    get_kb_item('ftp/'+port+'/broken')) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  ip = get_host_ip();
  last = ereg_replace(string:ip,
  		    pattern:"[0-9]*\.[0-9]*\.[0-9]*\.([0-9]*)$",
		    replace:"\1");
  last = (int(last) + 42) % 256;
  ip = strcat("169,254,", rand() % 256, ",", rand() % 256);
  ip = ereg_replace(string:ip, pattern:"\.", replace:",");
  ip = ereg_replace( pattern:"([0-9]*,[0-9]*,[0-9]*,)[0-9]*$",
  			replace:"\1",
			string:ip);
  ip = string(ip, last);			
  h  = str_replace(string:ip, find:',', replace:'.');
  command = string("PORT ", ip, ",42,42\r\n");
  send(socket:soc, data:command);
  code = ftp_recv_line(socket:soc);
  code = str_replace(string:code, find:'\r', replace:'');
  p = 42*256+42;
  if ( code =~ "^200" )
   security_hole(port:port, extra:'The following command, telling the server to connect to ' + h + ' on port ' + p + ':\n\n' + ( command - '\r')  + '\nproduced the following output:\n\n' + code);
 }
 close(soc);
 }
} 


