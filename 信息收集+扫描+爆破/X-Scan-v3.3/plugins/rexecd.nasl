#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10203);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0618");

 script_name(english:"rexecd Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The rexecd service is listening on the remote port." );
 script_set_attribute(attribute:"description", value:
"The rexecd service is open. This service is design to allow users of a 
network to execute commands remotely.

However, rexecd does not provide any good means of authentication, so it 
may be abused by an attacker to scan a third party host." );
 script_set_attribute(attribute:"solution", value:
"comment out the 'exec' line in /etc/inetd.conf and restart the inetd process" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();
 
 script_summary(english:"Checks for the presence of rexecd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc");
 script_family(english:"Service detection");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rexecd", 512);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/rexecd");
if(!port)
{
  port = 512;
  if (! service_is_unknown(port: port)) exit(0);
}

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

# This script will probably not work without credentials

cmd = strcat( "0", '\0',	# No separate channel for stderr
      	      "root", '\0',	# username
	      "FOOBAR", '\0',	# password
	      "id", '\0' );	# command

send(socket:soc, data: cmd);
r = recv_line(socket:soc, length:4096);
close(soc);
if (strlen(r) == 0) exit(0);
if (ord(r[0]) == 1) 
{
 if ( service_is_unknown ( port: port ) )
  	register_service(port:port, proto:"rexecd");

 security_warning(port);
}
