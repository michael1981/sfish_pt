#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15929);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-2004-2479");
  script_bugtraq_id(11865);
  script_xref(name:"OSVDB", value:"12282");

  script_name(english:"Squid Malformed Host Name Error Message Information Disclosure");
  script_summary(english:"Checks for the usage of a freed pointer");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host running a Squid proxy on this port.

There is a vulnerability in the remote version of this software which may
allow an attacker to disclose the content of its memory by causing the
use of a freed pointer.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the vendor released patch, for squid it is located here:
www.squid-cache.org.  You can also protect yourself by enabling
access lists on your proxy.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://bugs.squid-cache.org/show_bug.cgi?id=1143'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);
  exit(0);
}


include('http_func.inc');
include('http_keepalive.inc');


port = get_kb_item("Services/http_proxy");
if ( ! port ) port = 3128;
res = http_keepalive_send_recv(port:port, data:http_get(item:"http://./nessus.txt", port:port));

if ( "Squid" >< res && egrep(pattern:"http://[^./][^/]*/nessus\.txt", string:res) )
	security_warning(port);
