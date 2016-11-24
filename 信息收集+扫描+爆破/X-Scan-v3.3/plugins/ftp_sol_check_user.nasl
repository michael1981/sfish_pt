#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10653);
 script_bugtraq_id(2564);
 script_version ("$Revision: 1.12 $");
 script_xref(name:"OSVDB", value:"72");
 script_name(english:"Solaris FTP Daemon CWD Command Account Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to an account enumeration attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to determine the existence of a user on the remote
system by issuing the command CWD ~<username>, even before logging in.
An attacker can exploit this flaw to determine the existence of known
vulnerable accounts." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 
script_end_attributes();

 
 script_summary(english:"CWD ~root before logging in");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {	
	data = string("CWD ~nonexistinguser\r\n");
  	send(socket:soc, data:data);
  	a = ftp_recv_line(socket:soc);
  	if(egrep(pattern:"^550 Unknown user name after ~",
  	   string:a))security_warning(port);
  	ftp_close(socket:soc);
 }
}
