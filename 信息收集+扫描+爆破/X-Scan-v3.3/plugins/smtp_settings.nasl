#
# (C) Tenable Network Security, Inc.
#

# This script was written by Michel Arboi <arboi@alussinan.org>
# and merged with third_party_domain.nasl, which was written by
# Renaud Deraison <deraison@cvs.nessus.org>
#
# SMTP is defined by RFC 2821. Messages are defined by RFC 2822

# @PREFERENCES@

include( 'compat.inc' );

default_domain = "example.com";

if(description)
{
  script_id(11038);
  script_version ("$Revision: 1.9 $");

  script_name(english:"SMTP settings");
  script_summary(english:"SMTP settings");

  script_set_attribute(
    attribute:'synopsis',
    value:'Sets parameters used by other SMTP checks'
  );

  script_set_attribute(
    attribute:'description',
    value:'This script just sets a couple of SMTP parameters.

Several checks need to use a third party host/domain
name to work properly.

The checks that rely on this are SMTP or DNS relay checks.

By default, nessus.org is being used. However, under some
circumstances, this may make leak packets from your network
to this domain, thus compromising the privacy of your tests.

While the owner of \'nessus.org\' is not known to keep logs of
such packet traces, you may want to change this value to
maximize your privacy.

Note that you absolutely need this option to be set to a
*third party* domain. This means a domain that has *nothing
to do* with the domain name of the network you are testing.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'n/a'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.ietf.org/rfc/rfc2821.txt'
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_end_attributes();

  script_category(ACT_SETTINGS);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Settings");

  #
  script_add_preference(name:"Third party domain :", type:"entry", value:default_domain);
  script_add_preference(name:"From address : ", type:"entry", value:"nobody@example.com");
  script_add_preference(name:"To address : ", type:"entry", value:"postmaster@[AUTO_REPLACED_IP]");
  # AUTO_REPLACED_IP and AUTO_REPLACED_ADDR are... automatically replaced!
  exit(0);
}

#
# The script code starts here
#

fromaddr = script_get_preference("From address : ");
toaddr = script_get_preference("To address : ");

if (!fromaddr) fromaddr = "nessus@example.com";
if (! toaddr) toaddr = "postmaster@[AUTO_REPLACED_IP]";

if ("AUTO_REPLACED_IP" >< toaddr) {
  dstip = get_host_ip();
  toaddr = ereg_replace(pattern:"AUTO_REPLACED_IP", string:toaddr,
		replace: dstip);
}
if ("AUTO_REPLACED_ADDR" >< toaddr) {
  dstaddr = get_host_name();
  toaddr = ereg_replace(pattern:"AUTO_REPLACED_ADDR", string:toaddr,
		replace: dstaddr);
}

set_kb_item(name:"SMTP/headers/From", value:fromaddr);
set_kb_item(name:"SMTP/headers/To", value:toaddr);

domain = script_get_preference("Third party domain :");

if(!domain)domain = default_domain;
set_kb_item(name:"Settings/third_party_domain", value:domain);

exit(0);
