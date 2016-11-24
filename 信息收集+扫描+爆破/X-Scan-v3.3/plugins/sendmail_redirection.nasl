#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10250);
 script_version ("$Revision: 1.22 $");
 
 script_name(english: "Sendmail Redirection Relaying Allowed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is vulnerable to a redirection attack." );
 script_set_attribute(attribute:"description", value:
"The remote MTA is vulnerable to a redirection attack. That is, if a 
mail is sent to :

		user@hostname1@victim
		
Then the remote SMTP server (victim) will send the mail to :
		user@hostname1
		
Using this flaw, an attacker may route a message through your firewall, 
in order to exploit other SMTP servers that can not be reached from the
outside." );
 script_set_attribute(attribute:"solution", value:
"In sendmail.cf, at the top of ruleset 98, in /etc/sendmail.cf, insert 
the following statement :
R$*@$*@$*       $#error $@ 5.7.1 $: '551 Sorry, no redirections.'" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	

script_end_attributes();
 
 script_summary(english: "Redirection check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "SMTP problems");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl", "smtpserver_detect.nasl");
 script_exclude_keys("SMTP/postfix", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
  b = smtp_recv_banner(socket:soc);
  if(!b) exit(0);
  if ( "Sendmail" >!< b )exit(0);

  domain = ereg_replace(pattern:"[^\.]*\.(.*)",
 		       string:get_host_name(),
		       replace:"\1");		
  s = string("HELO ", domain, "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  s = string("MAIL FROM: root@", get_host_name(), "\r\n"); 
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  s = string("RCPT TO: root@host1@", get_host_name(), "\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:255);
  if(ereg(pattern:"^250 .*", string:r))security_warning(port);
  close(soc);
}
