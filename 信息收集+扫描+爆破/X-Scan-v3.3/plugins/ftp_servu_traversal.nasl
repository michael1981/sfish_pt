#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10565);
 script_bugtraq_id(2052);
 script_cve_id("CVE-2001-0054");
 script_xref(name:"OSVDB", value:"464");
 script_version ("$Revision: 1.28 $");
 
 script_name(english:"Serv-U CD Command Encoded Traversal Arbitrary File/Directory Access");
 script_summary(english:"Traverses the remote ftp root");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U FTP server. The installed version
fails to properly sanitize user supplied input to the 'cd' command. An
attacker could exploit this flaw to access arbitrary files on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0043.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U 2.5i or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(! login) login="ftp";
if (! pass) pass="test@nessus.com";

banner = get_ftp_banner(port:port);
if (! banner || "Serv-U FTP Server" >!< banner ) exit(0);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:pass))
 {
  
  for(i=0;i<2;i=i+1)
  {
  data = string("CWD ..%20.\r\n");
  send(socket:soc, data:data);
  a[i] = ftp_recv_line(socket:soc);
  }
  
  if(a[0]==a[1])exit(0);

  if((egrep(pattern:".*to /..", string:a[0])) ||
     (egrep(pattern:".*to /[a-z]:/", string:a[1], icase:TRUE)) ||
     (egrep(pattern:"^550 /[a-z]:/.*", string:a[1], icase:TRUE)))
    	security_warning(port);

  exit(0);   
 }
ftp_close(socket: soc);


r = get_ftp_banner(port: port);
if(!r)exit(0);
 if(egrep(pattern:"^220 Serv-U FTP-Server v2\.(([0-4][0-9])|(5[a-h]))", string:r))
 {
    report = string(
      "*** Note : Nessus solely relied on the banner as it was not possible\n",
      "*** to log into this server"
    );
 	security_warning(port:port, extra:report);
 }

