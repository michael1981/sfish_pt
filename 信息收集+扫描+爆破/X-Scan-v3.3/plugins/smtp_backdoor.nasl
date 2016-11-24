#
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 2645	On-Demand Mail Relay (ODMR) SMTP with Dynamic IP Addresses
#

include( 'compat.inc' );

if(description)
{
  script_id(18391);
  script_version ("$Revision: 1.8 $");

  script_name(english:"SMTP Server Non-standard Port Detection");
  script_summary(english: "An SMTP server is running on a non standard port");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote SMTP service is running on a non-standard port.'
  );

  script_set_attribute(
    attribute:'description',
    value:'This SMTP server is running on a non standard port.
This might be a backdoor set up by crackers to send spam
or even control your machine.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Check and clean your configuration'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.icir.org/vern/papers/backdoor/'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N'
  );

  script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp");
 exit(0);
}

#

port = get_kb_item("Services/smtp");
if (port && port != 25 && port != 366 && port != 465 && port != 587) security_warning(port);

# 25 SMTP
# 336 CommuniGate Pro SMTP Module
# 465 SMTP SSL
# 587 Submission (RFC 4409)
