#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10262);
 script_version ("$Revision: 1.43 $");

 script_cve_id("CVE-1999-0512", "CVE-2002-1278", "CVE-2003-0285");
 script_bugtraq_id(6118, 7580, 8196);
 script_xref(name:"OSVDB", value:"6066");
 script_xref(name:"OSVDB", value:"7993");

 script_name(english:"MTA Open Mail Relaying Allowed");
 
 script_set_attribute(attribute:"synopsis", value:
"An open SMTP relay is running on this port." );
 script_set_attribute(attribute:"description", value:
"The remote SMTP server seems to allow the relaying. This means that
it allows spammers to use your mail server to send their mails to
the world, thus wasting your network bandwidth.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your SMTP server so that it cannot be used as a relay 
any more.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
  script_end_attributes();

 script_summary(english:"Checks if the remote mail server can be used as a spam relay"); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl", "smtp_settings.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
include('network_func.inc');
include("smtp_func.inc");

if (is_private_addr()) exit(0);

# can't perform this test on localhost
if(islocalhost())exit(0);

# can't perform this test on the local net
#if(islocalnet())exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


function smtp_test_relay(tryauth)
{
 local_var crp, data, domain, i, r, soc;

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 if (!data) 
 {
  close(soc);
  exit(0);
 }
 domain = get_kb_item("Settings/third_party_domain");
 
 crp = string("HELO ", domain, "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^2[0-9][0-9] .*", string:data)) return(0);

 if(tryauth)
 {
  crp = string("AUTH CRAM-MD5\r\n");
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);

  crp = string("ZnJlZCA5ZTk1YWVlMDljNDBhZjJiODRhMGMyYjNiYmFlNzg2Z==\r\n");
  send(socket:soc, data:crp);
  data = recv_line(socket:soc, length:1024);
  if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);
 }

 crp = string("MAIL FROM: <test_1@", domain, ">\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!ereg(pattern:"^[2-3][0-9][0-9] .*", string:data)) return(0);

 crp = string("RCPT TO: <test_2@", domain, ">\r\n");
 send(socket:soc, data:crp);
 i = recv_line(socket:soc, length:1024);
 if(ereg(pattern:"^250 ", string:i))
  {
  send(socket:soc, data:string("DATA\r\n"));
  r = recv_line(socket:soc, length:1024);
  if(ereg(pattern:"^3[0-9][0-9] .*", string:r))
   {
   security_hole(port);
   set_kb_item(name:"SMTP/spam", value:TRUE);
   set_kb_item(name:"SMTP/" + port + "/spam", value:TRUE);
   }
  }
 close(soc);
}

smtp_test_relay(tryauth: 0);
smtp_test_relay(tryauth: 1);
