#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10256);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-0284");
 script_xref(name:"OSVDB", value:"202");
 
 script_name(english:"SLMail HELO Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server may be affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"There might be a buffer overflow when this MTA is issued the 'HELO'
command issued by a too long argument.  This problem may allow an
attacker to execute arbitrary code on this computer, subject to the
privileges under which the service operates, or to deny service to
legitimate users of the server." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD19990204.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 script_summary(english:"Overflows the remote SMTP server");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/postfix");
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
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!egrep(pattern:"^220 .*", string:s))
  {
   close(soc);
   exit(0);
  }
  
  
  c = string("HELO ", crap(1999), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
   close(soc);
   for (i = 0; i < 3; i ++)
   {
     sleep(i);
     soc = open_sock_tcp(port);
     if (soc) break;
   }
   if(soc) s = smtp_recv_banner(socket:soc);
   else s = NULL;
   if(!s)
   {
    set_kb_item(name:string("SMTP/", port, "/helo_overflow"), value:TRUE);
    security_hole(port);
   }
  }
  close(soc);
 }
}
