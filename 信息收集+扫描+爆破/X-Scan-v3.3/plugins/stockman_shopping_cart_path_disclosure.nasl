#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11568);
  script_version ("$Revision: 1.10 $");
  script_xref(name:"OSVDB", value:"53332");

  script_name(english:"StockMan Shopping Cart shop.plx Path Disclosure");
  script_summary(english:"determines the remote root path");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running the StockMan shopping cart.

There is a flaw in this version which may allow an attacker to obtain
the physical path to the remote web root by requesting a non-exisant
page through the \'shop.plx\' CGI.

An attacker may use this flaw to gain more knowledge about the setup
of the remote host.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to StockMan Shopping Cart Version 7.9 or newer'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
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
 req = http_get(item:string(loc, "/shop.plx/page=nessus"+rand()),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*Error opening HTML file: /.*/nessus", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
