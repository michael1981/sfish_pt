#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11051);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-0400");
 script_bugtraq_id(4936);
 script_xref(name:"OSVDB", value:"14878");
 script_xref(name:"IAVA", value:"2002-t-0010");
 
 script_name(english:"ISC BIND < 9.2.1 rdataset Parameter Malformed DNS Packet DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, 
is vulnerable to a remote denial of service attack.

An attacker may use this flaw to prevent this service from working
properly." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to bind 9.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
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

if(ereg(string:vers, pattern:"^9\.[01]\..*"))
{
 security_hole(53);
 exit(0);
}

if(ereg(string:vers, pattern:"^9\.2\.(0[^0-9]|1rc.*)"))
{
 security_hole(53);
 exit(0);
}
