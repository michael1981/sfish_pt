#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive and Securiteam

include( 'compat.inc' );

if(description)
{
  script_id(10493);
  script_version ("$Revision: 1.22 $");
  script_xref(name:"OSVDB", value:"392");

  script_name(english:"Simple Web Counter swc ctr Parameter Remote Overflow");
  script_summary(english:"Checks for the presence of /cgi-bin/swc");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The CGI \'swc\' (Simple Web Counter) is present and vulnerable
to a buffer overflow when issued a too long value to the
\'ctr=\' argument.

An attacker may use this flaw to gain a shell on this host'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Use another web counter, or patch this one by hand'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securiteam.com/unixfocus/5FP0O202AE.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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


foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/swc?ctr=", crap(500)),
 	        port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);

 if("Could not open input file" >< r)
 {
   soc = http_open_socket(port);
   req = http_get(item:string(dir, "/swc?ctr=", crap(5000)), port:port);
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   http_close_socket(soc);
   if(ereg(pattern:"HTTP/[0-9]\.[0-9] 500 ",
	   string:r))security_hole(port);
 }
}
