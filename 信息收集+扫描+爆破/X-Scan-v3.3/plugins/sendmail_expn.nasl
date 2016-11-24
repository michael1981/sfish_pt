#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10249);
 script_version ("$Revision: 1.45 $");

 script_xref(name:"OSVDB", value:"12551");
 
 script_name(english:"Multiple Mail Server EXPN/VRFY Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate the names of valid users on the remote
host." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server answers to the EXPN and/or VRFY commands. 

The EXPN command can be used to find the delivery address of mail
aliases, or even the full name of the recipients, and the VRFY command
may be used to check the validity of an account. 

Your mailer should not allow remote users to use any of these
commands, because it gives them too much information." );
 script_set_attribute(attribute:"solution", value:
"If you are using Sendmail, add the option :

	O PrivacyOptions=goaway

in /etc/sendmail.cf." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
script_end_attributes();

 script_summary(english:"EXPN and VRFY checks"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl","smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_exclude_keys("SMTP/wrapped");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = 25;
if(!get_port_state(port))exit(0);

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  info = "";

  b = smtp_recv_banner(socket:soc);
  if ( ! b ) exit(0);
  s = string("HELO example.com\r\n");
  send(socket:soc, data:s);
  r = smtp_recv_line(socket:soc);

  s = string("EXPN root\r\n");
  send(socket:soc, data:s);
  expn_root = r = smtp_recv_line(socket:soc);
  
  if(ereg(string:r, pattern:"^(250|550)(-| ).*$"))
  {
    # exim hack
    if(!ereg(string:r, pattern:"^550 EXPN not available.*$") &&
       !ereg(string:r, pattern:"^550.*Administrative prohibition.*$") &&
       !ereg(string:r, pattern:"^550.*Access denied.*$"))
    {
      info += '\nEXPN root produces the following output :\n\n' + expn_root + '\n';
      set_kb_item(name:"SMTP/expn",value:TRUE);
    } 
  } 

  s = string("VRFY root\r\n");
  send(socket:soc, data:s);
  vrfy_root = r = smtp_recv_line(socket:soc);
  if(ereg(string:r, pattern:"^(250|550)(-| ).*$"))
  {
    send(socket:soc, data:string("VRFY random", rand(), "\r\n"));
    r = smtp_recv_line(socket:soc);
    if(
      ereg(string:r, pattern:"^(250|550)(-| ).*$") &&
      substr(vrfy_root, 0, 2) != substr(r, 0, 2)
    )
    {
      info += '\nVRFY root produces the following output :\n\n' + vrfy_root + '\n';
      set_kb_item(name:"SMTP/vrfy",value:TRUE);
    }
  }

  if (info) security_warning(port:port, extra:info);
  close(soc);
}
