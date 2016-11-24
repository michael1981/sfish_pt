#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10084);
 script_version ("$Revision: 1.70 $");
 if ( NASL_LEVEL >= 2200 )
 {
  script_cve_id("CVE-1999-0219", "CVE-2000-0870", "CVE-2000-0943", "CVE-2000-1035",
                "CVE-2000-1194", "CVE-2002-0126", "CVE-2005-0634", "CVE-2005-1415");
  script_bugtraq_id(269, 1227, 1675, 1690, 1858, 3884, 7251, 7278, 7307, 12704, 13454);
 }
 script_xref(name:"OSVDB", value:"74");
 script_xref(name:"OSVDB", value:"1555");
 script_xref(name:"OSVDB", value:"1620");
 script_xref(name:"OSVDB", value:"6800");
 script_xref(name:"OSVDB", value:"11326");
 script_xref(name:"OSVDB", value:"12077");
 script_xref(name:"OSVDB", value:"14369");
 script_xref(name:"OSVDB", value:"16049");

 script_name(english:"Multiple FTP Server Command Handling Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote FTP server closes the connection when a command or argument
is too long.  This is probably due to a buffer overflow and may allow
an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade / switch the FTP server software or disable the service if not
needed." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "attempts some buffer overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/password");
# script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (! get_port_state(port) || 
    get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);


function is_vulnerable (value)
{
 local_var soc;

 soc = open_sock_tcp (port);
 if (!soc)
 {
   set_kb_item(name:"ftp/overflow", value:TRUE);
   set_kb_item(name:"ftp/overflow_method", value:value);
   security_hole(port);
 }
 exit (0);
}

 soc = open_sock_tcp(port);
 if(soc)
 {
  d = ftp_recv_line(socket:soc);
  if(!d){
	set_kb_item(name:"ftp/false_ftp", value:TRUE);
	close(soc);
	exit(0);
	}
  if(!egrep(pattern:"^220[ -]", string:d))
   {
    # not an FTP server
    set_kb_item(name:"ftp/false_ftp", value:TRUE);
    close(soc);
    exit(0);	
   }
 
  if("Microsoft FTP Service" >< d)exit(0);
 
  req = string("USER ftp\r\n");
  send(socket:soc, data:req);
  d = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!d)
  {
   set_kb_item(name:"ftp/false_ftp", value:TRUE);
   exit(0);	
  }
  
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);
  d = ftp_recv_line(socket:soc);
  s = string("USER ", crap(4096), "\r\n");
  send(socket:soc, data:s);
  d = ftp_recv_line(socket:soc);
  if(!d){
	close (soc);
	is_vulnerable (value:"USER");
	}
  else
  {
   # Let's try to access it with valid credentials now.
   login = get_kb_item("ftp/login");
   password = get_kb_item("ftp/password");

   s = string("USER ", login, "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   # ProFTPD 1.5.2 crashes with more than 12 KB
   s = string("PASS ", crap(12500), "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   if(!d){
	close (soc);
	is_vulnerable (value:"PASS");
	}
   else
   {
     s = string("PASS ", password, "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d) exit(0);

     s = string("CWD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"CWD");
	}
	
     s = string("LIST ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"LIST");
	}
	
		
     s = string("STOR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"STOR");
	}
	
     s = string("RNTO ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNTO");
	}
	
     s = string("MKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"MKD");
	}	
		
     s = string("XMKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XMKD");
	}
	
     s = string("RMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RMD");
	exit(0);
	}	


     s = string("XRMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XRMD");
	}	
	
     s = string("APPE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"APPE");
	}
	
     s = string("SIZE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"SIZE");
	}
	
     s = string("RNFR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNFR");
	}
	
				
     s = string("HELP ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"HELP");
	}

     s = string(crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"");
	}
     }
    }
   if ( soc )  close(soc);
  }
