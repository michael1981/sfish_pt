#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10260);
  script_version ("$Revision: 1.38 $");

  script_cve_id("CVE-1999-0098", "CVE-1999-1015", "CVE-1999-1504");
  script_bugtraq_id(61, 62);
  script_xref(name:"OSVDB", value:"205");
  script_xref(name:"OSVDB", value:"5855");
  script_xref(name:"OSVDB", value:"5970");
  script_xref(name:"OSVDB", value:"6034");

  script_name(english:"Multiple MTA HELO Command Remote Overflow");
  script_summary(english:"Checks if the remote mail server can be used to send anonymous mail");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote SMTP server is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote SMTP server seems to allow remote users to
send mail anonymously by providing arguments that are
too long to the HELO command (more than 1024 chars).

This problem may allow malicious users to send hate
mail or threatening mail using your server,
and keep their anonymity.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'If you are using sendmail, upgrade to version 8.9.x or newer.
If you do not run sendmail, contact your vendor.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=90221101925991&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl", "sendmail_expn.nasl", "smtpserver_detect.nasl", "smtpscan.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/microsoft_esmtp_5", "SMTP/postfix", "SMTP/domino");
 script_require_keys("SMTP/sendmail");
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

sig = get_kb_item(string("smtp/", port, "/real_banner"));
if ( sig && "Sendmail" >!< sig ) exit(0);
banner = get_smtp_banner(port:port);
if("Sendmail" >!< banner) exit(0);


if(safe_checks())
{
  if("Sendmail" >< banner)
  {
   version = ereg_replace(string:banner,
                         pattern:".* Sendmail (.*)/.*",
                         replace:"\1");

  if(ereg(string:version, pattern:"((^[0-7]\..*)|(^8\.[0-8]\..*))"))
  {
   alrt =
"You are running a version of Sendmail which is older
than version 8.9.0.

There's a flaw in this version which allows people to send
mail anonymously through this server (their IP won't be shown
to the recipient), through a buffer overflow in the HELO
command.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to sendmail 8.9.0 or newer
Risk factor : Low";

   security_hole(port:port, extra:alrt);
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
 if (!data)
 {
  close(soc);
  exit(0);
 }
 crp = string("HELO ", crap(1030), "\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:4);
 if(data == "250 ") security_hole(port);
 close(soc);
 }
}
