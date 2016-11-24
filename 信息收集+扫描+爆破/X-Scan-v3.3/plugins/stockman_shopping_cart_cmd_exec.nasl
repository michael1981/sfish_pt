#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11569);
  script_version ("$Revision: 1.10 $");
  script_bugtraq_id(7485);
  script_xref(name:"OSVDB", value:"53331");

  script_name(english:"StockMan Shopping Cart shop.plx page Parameter Arbitrary Command Execution");
  script_summary(english:"Determines the version of shop.plx");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to authentication bypass.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the StockMan shopping cart.

According to the version number of the CGI shop.plx, there is
a flaw in this installation which may allow an attacker to
execute arbitrary commands on this host, and which may even
allow him to obtain your list of customers or their credit
card number.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to StockMan Shopping Cart Version 7.9 or newer'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);



function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/shop.plx"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"Stockman Shopping Cart Version ([0-6]\.|7\.[0-8])", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
