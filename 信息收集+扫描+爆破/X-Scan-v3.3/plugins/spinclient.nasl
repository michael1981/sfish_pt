#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to Tollef Fog Heen <tfheen@opera.no> for his help

include( 'compat.inc' );

if(description)
{
 script_id(10393);
 script_version ("$Revision: 1.18 $");
 script_xref(name:"OSVDB", value:"54034");

 script_name(english:"spin_client.cgi Remote Overflow");
 script_summary(english:"Checks for the /cgi-bin/spin_client.cgi buffer overrun");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:'There is a buffer overrun in the \'spin_client.cgi\'
CGI program, which will allow anyone to execute arbitrary
commands with the same privileges as the web server (root or nobody).'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Remove \'spin_client.cgi\' from the server or contact your vendor for a fix'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# This CGI is tricky to check for.
#
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/spin_client.cgi"), port:port))
 {
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("GET ", dir, "/spin_client.cgi?",crap(8)," HTTP/1.0\r\n");
  req = req + string("User-Agent: ", crap(8), "\r\n\r\n");
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:1024);
  close(soc);
  if(ereg(pattern:"^HTTP\/[0-9]\.[0-9] 200 ",
   	  string:r))
   {
   soc = open_sock_tcp(port);
   req = string("GET ", dir, "/spin_client.cgi?",crap(8000), " HTTP/1.0\r\n");
   req = req + string("User-Agent: ", crap(8000), "\r\n\r\n");
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   if(ereg(pattern:"^HTTP\/[0-9]\.[0-9] 500 ",
   	  string:r))
   {
   	security_hole(port);
   }
  }
 }
 else exit(0);
 }
}
