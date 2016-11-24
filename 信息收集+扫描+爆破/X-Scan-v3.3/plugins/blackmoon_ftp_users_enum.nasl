#
# (C) Tenable Network Security, Inc.
#
# ref: http://marc.info/?l=bugtraq&m=105353283720837&w=2
#


include("compat.inc");


if(description)
{
 script_id(11648);
 script_cve_id("CVE-2003-0343");
 script_bugtraq_id(7647);
 script_xref(name:"OSVDB", value:"12079");
 script_xref(name:"Secunia", value:"8840");
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"BlackMoon FTP Login Error Message User Enumeration");
 script_summary(english:"Checks for the ftp login error message");
	     
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a user enumeration vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of BlackMoon FTP running on the remote host issues a\n",
     "special error message when a user attempts to log in using a\n",
     "nonexistent account.\n\n",
     "An attacker may use this flaw to make a list of valid accounts,\n",
     "which can be used to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=105353283720837&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BlackMoon FTP."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "logins.nasl", "smtp_settings.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 banner = ftp_recv_line(socket:soc);
 if(!banner)exit(0);
 send(socket:soc, data:string("USER nessus", rand(), rand(), "\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 
 send(socket:soc, data:string("PASS whatever\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r) exit(0);
 close(soc);
 if("530-Account does not exist" >< r) security_warning(port);
}
