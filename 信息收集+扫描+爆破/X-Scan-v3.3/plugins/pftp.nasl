#
# (C) Tenable Network Security, Inc.
#

# Thanks to Overlord <mail_collect@gmx.net> for supplying me
# with the information for this problem as well as a copy of a
# vulnerable version of PFTP


include("compat.inc");

if(description)
{
 script_id(10508);
 script_xref(name:"OSVDB", value:"407");
 script_version ("$Revision: 1.10 $");
 script_name(english: "PFTP Default Unpassworded Account");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to login to the remote system with an 
unpassworded acccount." );

 script_set_attribute(attribute:"description", value:
"It is possible to log into the remote FTP server as ' '/' '.
If the remote server is PFTP, then anyone can use this 
account to read arbitrary files on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade PFTP to version 2.9g" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();
 
 script_summary(english:"Checks for a blank account");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", 
	"ftp_kibuv_worm.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/backdoor') ||
    get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/AnyUser') ) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:" ", pass:" "))
  {
   security_hole(port);
   set_kb_item(name:"ftp/pftp_login_problem", value:TRUE);
  }
  close(soc);
 }
