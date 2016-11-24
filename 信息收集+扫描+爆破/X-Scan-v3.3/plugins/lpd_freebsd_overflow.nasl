#
# (C) Tenable Network Security, Inc.
#

# This is a check for an OLD flaw
#


include("compat.inc");

if(description)
{
   script_id(11354);
   script_version ("$Revision: 1.7 $");
   script_cve_id("CVE-1999-0299");
   script_xref(name:"OSVDB", value:"6093");

   script_name(english:"FreeBSD 2.x lpd Long DNS Hostname Overflow");
  
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote lpd daemon seems to be vulnerable to a buffer overflow when
a host with a too long DNS host name connects to it.

*** Nessus solely relied on the version of the remote
*** operating system to issue an alert, so this
*** might be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=99892644616749&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FreeBSD 3.x." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
   script_summary(english:"Determines if lpd is running");
   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
   script_family(english:"Gain a shell remotely");
   script_require_ports("Services/lpd", 515);
   script_dependencies("find_service1.nasl", "os_fingerprint.nasl");
 
   exit(0);
}



#
# The code starts here
#

os = get_kb_item("Host/OS");
if(!os)exit(0);
if("FreeBSD 2" >!< os)exit(0);

port = get_kb_item("Services/lpd");
if(!port)port = 515;

soc = open_sock_tcp(port);
if(!soc)exit(0);
else security_hole(port);
