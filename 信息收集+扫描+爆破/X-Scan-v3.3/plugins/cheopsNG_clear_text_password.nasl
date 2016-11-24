#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20162);
 script_version ("$Revision: 1.7 $");
 script_name(english:"Cheops NG Cleartext Authentication Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Cheops NG agent is affected by an information disclosure
issue." );
 script_set_attribute(attribute:"description", value:
"A Cheops NG agent is running on this port.  Users with a valid account
on the remote host can connect to this service and use it to map your
network, portscan machines and identify running services. 

The agent is configured to allow unencrypted connections, which may
allow passwords, that are transmitted in cleartext, to be sniffed. 

In addition, it is possible to brute force login/passwords on the
remote host using this agent." );
 script_set_attribute(attribute:"solution", value:
"Configure Cheops to run on top of SSL or block this port from outside
communication if you want to further restrict the use of Cheops." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english: "Cheops NG agent uses clear text passwords");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("cheopsNG_detect.nasl");
 script_require_keys("cheopsNG/password");
 exit(0);
}

port = get_kb_item("cheopsNG/password");
if (port && get_port_transport(port) == ENCAPS_IP ) security_warning(port);
