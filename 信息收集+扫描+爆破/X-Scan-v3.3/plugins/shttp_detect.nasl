#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11720);
 script_version ("$Revision: 1.9 $");
 
 script_name(english:"Secure HyperText Transfer Protocol (S-HTTP) Detection");
 script_summary(english:"Checks if the web server accepts the Secure method");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server encrypts traffic using an obsolete protocol."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote web server accepts connections encrypted using Secure\n",
   "HyperText Transfer Protocol (S-HTTP), a cryptographic layer that was\n",
   "defined in 1999 by RFC 2660 and never widely implemented."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://tools.ietf.org/html/rfc2660"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Rare or obsolete code is often poorly tested. Thus, it would be\n",
   "safer to disable support for S-HTTP and use HTTPS instead."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);
req = string("Secure * Secure-HTTP/1.4\r\n",
		"Host: ", get_host_name(), ":", port, "\r\n",
		"Connection: close\r\n",
		"\r\n");
send(socket: soc, data: req);
r = recv_line(socket: soc, length: 256);
http_close_socket(soc);
if (ereg(pattern:"Secure-HTTP/[0-9]\.[0-9] 200 ", string:r)) security_warning(port);
