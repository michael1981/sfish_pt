#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(11020);
  script_version("$Revision: 1.14 $");
  script_cve_id("CVE-2001-0319");
  script_bugtraq_id(2350);
  script_xref(name:"OSVDB", value:"833");

  script_name(english:"IBM Net.Commerce orderdspc.d2w order_rn Option SQL Injection");
  script_summary(english:"Determine if the remote host is vulnerable to SQL injection");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to SQL injection.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The macro orderdspc.d2w in the remote IBM Net.Commerce 3x
is vulnerable to an SQL injection attack via the 'order_rn'
option.

An attacker may use it to abuse your database in many ways."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to IBM WebSphere Commerce Suite version 5.1 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2001-02/0072.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ibm-http");
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
if(!port || !get_port_state(port))exit(0);
req = http_get(item:"/cgi-bin/ncommerce3/ExecMacro/orderdspc.d2w/report?order_rn=9';", port:port);

res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

expect1 = "A database error occurred.";
expect2 = "SQL Error Code";
if((expect1 >< res) && (expect2 >< res))
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
