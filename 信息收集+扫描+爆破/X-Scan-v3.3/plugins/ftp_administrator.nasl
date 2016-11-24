#
# This script was written by Keith Young <Keith.Young@co.mo.md.us>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)

include("compat.inc");

if(description)
{
 script_id(11160);
 script_version ("$Revision: 1.8 $");

 script_name(english:"Windows FTP Server NULL Administrator Password");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read, written or deleted on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote server is incorrectly configured with a NULL password for the
user 'Administrator' and has FTP enabled." );
 script_set_attribute(attribute:"solution", value:
"Change the Administrator password on this host." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_summary(english:"Checks for a NULL Windows Administrator FTP password");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Keith Young");
 
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if (! get_port_state(port)) exit(0);

if (get_kb_item('ftp/'+port+'/broken') ||
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"Administrator", pass:""))security_hole(port);
 }
