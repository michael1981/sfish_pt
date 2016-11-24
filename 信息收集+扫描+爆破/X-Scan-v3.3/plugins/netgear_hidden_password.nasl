#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12258);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-2556", "CVE-2004-2557");
 script_bugtraq_id(10459);
 script_xref(name:"OSVDB", value:"6743");

 script_name(english:"NETGEAR Wireless Access Point Hardcoded Default Password");

 script_set_attribute(attribute:"synopsis", value:
"The remote network device can be accessed using an undocumented
administrative account." );
 script_set_attribute(attribute:"description", value:
"NETGEAR ships at least one device with a built-in administrator
account.  This account cannot be changed via the configuration
interface and enables a remote attacker to control the NETGEAR device. 

To duplicate this error, simply point your browser to a vulnerable
machine, and log in (when prompted) with :

  userid = super
  password = 5777364

or :

  userid = superman
  password = 21241036" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-06/0036.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-06/0077.html" );
 script_set_attribute(attribute:"see_also", value:"http://kbserver.netgear.com/kb_web_files/n101383.asp" );
 script_set_attribute(attribute:"solution", value:
"Contact vendor for a fix.  As a temporary workaround, disable the
webserver or filter the traffic to the NETGEAR webserver via an
upstream firewall." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english: "NETGEAR Hidden Password Check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) 
	exit(0); 

init = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\n\r\n");

auth[0] = "c3VwZXJtYW46MjEyNDEwMzY=";
auth[1] = "c3VwZXI6NTc3NzM2NA==";




reply = http_keepalive_send_recv(data:init, port:port, embedded:TRUE);
if ( reply == NULL ) exit(0);

if ( egrep(pattern:"HTTP/.* 40[13] ", string:reply ) )
{
     for ( i = 0 ; auth[i] ; i ++ )
     {
	req = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), 
		     "\r\nAuthorization: Basic ", auth[i], "\r\n\r\n");

	reply = http_keepalive_send_recv(data:req, port:port, embedded:TRUE);
	if ( (egrep(string:reply, pattern:"^HTTP/1\.. 200 OK")) && 
	   ("NETGEAR" >< reply) )
	{
		security_warning(port);
		exit(0);
	}
      }
}

