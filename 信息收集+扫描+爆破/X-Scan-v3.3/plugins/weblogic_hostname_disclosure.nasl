#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11606);
  script_version ("$Revision: 1.11 $");
  script_bugtraq_id(7257);
  script_xref(name:"OSVDB", value:"5737");

  script_name(english:"WebLogic Crafted GET Request Hostname Disclosure");
  script_summary(english:"Make a request like GET . \r\n\r\n");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote WebLogic server discloses its NetBIOS host name when it is
issued a request generating a redirection.

An attacker may use this information to better prepare
other attacks against this host."
  );

  script_set_attribute(
    attribute:'solution',
    value: 'Currently, there are no known upgrades or patches to correct this issue.
Filter requests that start with a "." in a proxy or firewall with URL filtering capabilities.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2003-04/0034.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

w = http_send_recv_buf(port: port, data: 'GET . HTTP/1.0\r\n\r\n');
if (isnull(w)) exit(0);

r = strcat(w[0], w[1], '\r\n', w[2]);

if("WebLogic" >< r)
{
 loc =egrep(string:r, pattern:"^Location");
 if(!loc)exit(0);
 name = ereg_replace(pattern:"^Location: http://([^/]*)/.*",
 		     replace:"\1",
		     string:loc);

 if ( name == loc ) exit(0);
 if(get_host_name() == name)exit(0);
 if(get_host_ip() == name)exit(0);

 report = "We determined that the remote host name is : '" + name + "'";

security_warning(port:port, extra:report);
}
