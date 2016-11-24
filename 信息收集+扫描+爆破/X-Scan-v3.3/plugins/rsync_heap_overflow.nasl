#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11943);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-0962");
 script_bugtraq_id(9153);
 script_xref(name:"OSVDB", value:"2898");
 script_xref(name:"IAVA", value:"2003-t-0024");
 script_xref(name:"RHSA", value:"RHSA-2003:398-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:050");
 
 script_name(english:"rsync < 2.5.7 Unspecified Remote Heap Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote rsync server might be vulnerable to a heap overflow.
An attacker may use this flaw to gain a shell on this host

*** Since rsync does not advertise its version number and since there 
*** are little details about this flaw at this time, this might be a 
*** false positive" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to rsync 2.5.7" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines if rsync is running");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security");
 script_dependencies("rsync_modules.nasl");
 script_require_ports("Services/rsync", 873);
 exit(0);
}

port = get_kb_item("Services/rsync");
if(!port)port = 873;
if(!get_port_state(port))exit(0);


welcome = get_kb_item("rsync/" + port + "/banner");
if ( ! welcome )
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 welcome = recv_line(socket:soc, length:4096);
 if(!welcome)exit(0);
}




#
# rsyncd speaking protocol 26 or older *MIGHT* be vulnerable
#

if(ereg(pattern:"@RSYNCD: (1[0-9]|2[0-6])[^0-9]", string:welcome))
{
 security_hole(port);
}
