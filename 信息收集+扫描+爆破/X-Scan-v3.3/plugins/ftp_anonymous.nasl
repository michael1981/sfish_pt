#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10079);
 script_version ("$Revision: 1.44 $");
 script_cve_id("CVE-1999-0497");
 script_xref(name:"OSVDB", value:"69");

 script_name(english:"Anonymous FTP Enabled");
	     
 script_set_attribute(attribute:"synopsis", value:
"Anonymous logins are allowed on the remote FTP server." );
 script_set_attribute(attribute:"description", value:
"This FTP service allows anonymous logins. Any remote user may connect
and authenticate without providing a password or unique credentials. 
This allows a user to access any files made available on the FTP server." );
 script_set_attribute(attribute:"solution", value:
"Disable anonymous FTP if it is not required. Routinely check the FTP 
server to ensure sensitive content is not available." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks if the remote ftp server accepts anonymous logins");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("logins.nasl", "smtp_settings.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor')
    || get_kb_item('ftp/'+port+'/broken')) exit(0);

state = get_port_state(port);
if(!state)exit(0);
soc = open_sock_tcp(port);
if(soc)
{
 domain = get_kb_item("Settings/third_party_domain");
 r = ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", domain));
 if(r)
 {
  port2 = ftp_pasv(socket:soc);
  if(port2)
  {
   soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
   if (soc2)
   {
    send(socket:soc, data:'LIST\r\n');
    listing = ftp_recv_listing(socket:soc2);
    close(soc2);
    }
  }
  

  if(strlen(listing))
  {
   report = string ("The contents of the remote FTP root are :\n",
		listing);
  }
  else
    report = desc["english"];
 
 
  security_warning(port:port, extra: report);
  set_kb_item(name:"ftp/anonymous", value:TRUE);
  user_password = get_kb_item("ftp/password");
  if(!user_password)
  {
   set_kb_item(name:"ftp/login", value:"anonymous");
   set_kb_item(name:"ftp/password", value:string("nessus@", domain));
  }
 }
 close(soc);
}


