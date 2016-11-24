#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10885);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0055");
 script_bugtraq_id(4204);
 script_xref(name:"OSVDB", value:"732");

 script_name(english:"Microsoft Windows SMTP Service Malformed BDAT Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote SMTP server fail and restart by 
sending specially crafted 'BDAT' requests. 

The service will restart automatically, but all the connections
established at the time of the attack will be dropped.

An attacker may use this flaw to make mail delivery to your site
less efficient." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS02-012.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=101558498401274&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://www.digitaloffense.net/mssmtp/mssmtp_dos.pl" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Checks if the remote SMTP server can be restarted");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc); 
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .* Hello .*", string:data)))exit(0);
 
 
 crp = string("MAIL FROM: nessus@nessus.org\r\n");
 
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("RCPT TO: Administrator\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("BDAT 4\r\n");
 send(socket:soc, data:crp);
 crp = string("b00mAUTH LOGIN\r\n");
 send(socket:soc, data:crp);
 r = recv_line(socket:soc, length:255);
 if(ereg(pattern:"^250 .*", string:r))
 {
 r = recv_line(socket:soc, length:5);
 
 
 # Patched server say : "503 5.5.2 BDAT Expected"
 # Vulnerable servers say : "334 VXNlcm5hbWU6"
 if(ereg(pattern:"^334 .*",string:r))
 		security_warning(port);
 }
  send(socket:soc, data:string("QUIT\r\n"));
  close(soc);
  exit(0);	     
}
