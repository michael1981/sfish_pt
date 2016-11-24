#
# (C) Tenable Network Security, Inc.
#

# Testing for this flaw is really hard. 


include("compat.inc");

if(description)
{
   script_id(11406);
   script_version ("$Revision: 1.10 $");
   script_cve_id("CVE-2001-0670", "CVE-1999-0061");
   script_bugtraq_id(3252);
   script_xref(name:"OSVDB", value:"1945");
   script_xref(name:"IAVA", value:"2001-t-0015");

   script_name(english:"BSD in.lpd File Name Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote bsd-lpd daemon might be vulnerable to a buffer overflow
when sent a too long file name and then asked to show the print queue
when the file is being printed.

An attacker may use this flaw to gain a shell on this host.

** Because of the conditions to positively check for
** this flaw are very hard to meet, this alert might be 
** a false positive.

Affected systems : BSD/OS (up to 4.1), FreeBSD (up to 4.2), 
                   NetBSD (up to 1.5.1), OpenBSD (up to 2.9),
		   SuSE Linux (up to 7.2), SCO Open Server (5.0.6)" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
   script_summary(english:"Determines if the remote lpd is bsd-lpd");
   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
   script_family(english:"Gain a shell remotely");
   script_require_ports("Services/lpd", 515);
   script_dependencies("find_service1.nasl");
 
   exit(0);
}



#
# The code starts here
#


port = get_kb_item("Services/lpd");
if(!port)port = 515;

# We connect from an unprivileged port. BSD lpd will complain, others
# won't. This is very prone to false positives, but there is no way to
# detect the flaw "for sure".
#
soc = open_sock_tcp(port);
if(soc)
{ 
 r = recv_line(socket:soc, length:4096);
 if( r == NULL ) exit(0);
 if((" from invalid port" >< r) ||
    ("malformed from-address" >< r ))security_hole(port);
}
