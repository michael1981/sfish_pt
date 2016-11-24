#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10923);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2002-0068");
  script_bugtraq_id(4148);
  script_xref(name:"OSVDB", value:"5378");

  script_name(english:"Squid FTP URL Special Character Handling Remote Overflow");
  script_summary(english:"Determines squid version");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote squid caching proxy, according to its version number,
is vulnerable to various buffer overflows.

An attacker may use these to gain a shell on this system.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to squid 2.4.STABLE7 or newer'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.squid-cache.org/Advisories/SQUID-2002_1.txt'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/http_proxy",3128, 8080);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/http_proxy");
if(!port)
{
 if(get_port_state(3128))
 {
  port = 3128;
 }
 else port = 8080;
}

if(get_port_state(port))
{
  res = http_get_cache(item:"/", port:port);
  if(egrep(pattern:"Squid/2\.([0-3]\.|4\.STABLE[0-6]([^0-9]|$))", string:res))
      security_hole(port);
}
