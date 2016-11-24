#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# Date: Thu, 20 Mar 2003 18:46:59 +0100
# From: Niels Heinen <niels.heinen@ubizen.com>
# Subject: IBM Tivoli Firewall Security Toolbox buffer overflow vulnerability
# To: bugtraq@securityfocus.com 
# Message-id: <3E79FE93.5040407@ubizen.com


include("compat.inc");

if(description)
{
 script_id(11434);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2003-1104");
 script_bugtraq_id(7154, 7157);
 script_xref(name:"OSVDB", value:"16022");

 script_name(english:"IBM Tivoli Firewall Toolbox (TFST) Unspecified Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote service (probably the Tivoli Relay daemon) is 
vulnerable to a buffer overflow when it receives a long 
string.

An attacker may use this flaw to execute arbitrary code 
on this host (with the privilege of the user 'nobody')." );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.software.ibm.com/software/tivoli_support/patches/patches_1.3" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor supplied patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 
script_end_attributes();

 
 script_summary(english:"Tests for the overflow in Tivoli relay daemon");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");
 script_require_ports(9400);
 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

if(get_port_state(9400))
{ 
 soc = open_sock_tcp(9400);
 if(!soc)exit(0);
 
 send(socket:soc, data:string(crap(238), "\r\n"));
 r = recv(socket:soc, length:1024);
 close(soc);
 
 soc2 = open_sock_tcp(9400);
 if(!soc2)security_hole(9400);
}
