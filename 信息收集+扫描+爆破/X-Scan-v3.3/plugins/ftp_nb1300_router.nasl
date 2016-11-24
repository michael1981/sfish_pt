#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: 15 Apr 2003 00:34:13 -0000
#  From: denote <denote@freemail.com.au>
#  To: bugtraq@securityfocus.com
#  Subject: nb1300 router - default settings expose password
#


include("compat.inc");

if(description)
{
 script_id(11539);
 script_bugtraq_id(7359);
 script_xref(name:"OSVDB", value:"51636");
 script_version ("$Revision: 1.9 $");
 script_name(english:"NetComm NB1300 Router FTP Default Admin Account");
 script_summary(english:"Checks for admin/password");

 script_set_attribute(attribute:"synopsis", value:
"The remote router uses default credentials." );
 script_set_attribute(attribute:"description", value:
"It is possible to log into the remote FTP server with the username
'admin' and the password 'password'.

If the remote host is a NB1300 router, this would allow an attacker to
steal the WAN credentials of the user, or even to reconfigure the
router remotely." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0202.html" );
 script_set_attribute(attribute:"solution", value:
"Change the admin password on this host." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", 
	"ftp_kibuv_worm.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
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
  if(ftp_authenticate(socket:soc, user:"admin", pass:"password"))security_hole(port);
 }

