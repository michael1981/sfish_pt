#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10284);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-1516");
 script_xref(name:"OSVDB", value:"224");
 
 script_name(english:"TFS SMTP 3.2 MAIL FROM overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"There seem to be a buffer overflow in the remote SMTP server
when the server is issued a too long argument to the 'MAIL FROM'
command.

This problem may allow an attacker to prevent this host
to act as a mail host and may even allow him to execute
arbitrary code on this system." );
 script_set_attribute(attribute:"solution", value:
"If you are using TFS SMTP, upgrade to version 4.0.
If you do not, then inform your vendor of this vulnerability
and wait for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Overflows a buffer in the remote mail server"); 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/postfix", "SMTP/qmail");
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

if(safe_checks())
{ 
 banner = get_smtp_banner(port:port);
 
 if(banner)
 {
  if(egrep(string:banner,
  	  pattern:"TFS SMTP Server [1-3]\..*"))
	  {
            report = string(
                  "\n",
                  "The remote SMTP server responded with the following banner : ","\n\n",
                  banner,"\n\n",
                  "Note that Nessus only checked the version in the banner because safe\n",
                  "checks were enabled for this scan.\n"
                );
   	  security_hole(port:port, extra:report);
	  }
 }
 
 exit(0);
}
else
{
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);	
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if("250 " >< data)
 {
 crp = string("MAIL FROM: ", crap(1024), "\r\n");
 send(socket:soc, data:crp);
 buf = recv_line(socket:soc, length:1024);
 if(!buf){
  close(soc);
  for (i = 0; i < 3; i ++)
  {
    sleep(i);
    soc = open_sock_tcp(port);
    if (soc) break;
  }
  if ( soc ) s  = smtp_recv_banner(socket:soc);
  else s = NULL;
  
  if(!s){
	 security_hole(port);
	 set_kb_item(name:string("SMTP/", port, "/mail_from_overflow"), value:TRUE);
	}
			
  }
 }
 close(soc);
 }
}
}
