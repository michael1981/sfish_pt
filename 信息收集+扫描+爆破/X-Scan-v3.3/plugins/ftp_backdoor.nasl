#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10080);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0452");
 script_name(english:"Linux FTP Server Backdoor");
 script_summary(english:"Checks for the NULL ftpd backdoor");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a backdoor." );
 script_set_attribute(attribute:"description", value:
"There is a backdoor in the old FTP daemons of Linux, which allows
remote users to log in as 'NULL', with password 'NULL'. These
credentials provide root access." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your FTP server to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 
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
if (! soc) exit(0);

if (ftp_authenticate(socket:soc, user:"NULL", pass:"NULL"))
   security_hole(port);
close(soc);
