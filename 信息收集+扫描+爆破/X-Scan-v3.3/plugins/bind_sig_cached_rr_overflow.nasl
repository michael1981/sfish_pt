#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11152);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-1219");
 script_bugtraq_id(6160);
 script_xref(name:"OSVDB", value:"869");
 script_xref(name:"IAVA", value:"2002-A-0011");
 script_xref(name:"IAVA", value:"2002-a-0006");
 script_xref(name:"SuSE", value:"SUSE-SA:2002:044");
 script_xref(name:"Secunia", value:"7494");
 
 script_name(english:"ISC BIND named SIG Resource Server Response RR Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is affected
by the 'SIG cached RR overflow' vulnerability. 

An attacker may use this flaw to gain a shell on this system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.2.7, 8.3.4 or 4.9.11." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_end_attributes();
 
 script_summary(english:"Checks the remote BIND version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.2\.[0-6][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^8\.3\.[0-3][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^4\.9\.([0-9][^0-9]*$|10)"))security_hole(53);	 	 
