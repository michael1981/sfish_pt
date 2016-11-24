#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11510);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0684");
 script_bugtraq_id(7228);
 script_xref(name:"OSVDB", value:"14432");
 script_xref(name:"IAVA", value:"2003-B-0001");

 script_name(english:"ISC BIND < 4.9.5 DNS Resolver Functions Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is vulnerable
to a remote buffer overflow within its resolver code.

An attacker may be able to execute arbitrary code by having
the remote DNS server make a request and send back a malicious
DNS response with an invalid length field." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/308" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 4.9.5 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


 script_end_attributes();
 
 script_summary(english:"Checks the remote BIND version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}


vers = get_kb_item("bind/version");
if(!vers)exit(0);

vers = string(vers);
if(vers[0] == "4") 
{ 
 if(ereg(string:vers, pattern:"^4\.([0-8]\..*|9\.[0-4]([^0-9]|$))"))
 {
  security_hole(port:53, proto:"udp");
  exit(0);
 }
}
