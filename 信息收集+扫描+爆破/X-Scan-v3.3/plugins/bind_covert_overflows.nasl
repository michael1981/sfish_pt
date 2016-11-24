#
# (C) Tenable Network Security, inc.
#


include("compat.inc");

if(description)
{
 script_id(10605);
 script_xref(name:"IAVA", value:"2001-a-0001");
 script_bugtraq_id(2302, 2307, 2309, 2321);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-0010", "CVE-2001-0011", "CVE-2001-0012", "CVE-2001-0013");
 script_xref(name:"OSVDB", value:"1746");
 script_xref(name:"OSVDB", value:"1747");
 script_xref(name:"OSVDB", value:"1751");
 script_xref(name:"OSVDB", value:"14795");
 
 script_name(english:"ISC BIND < 4.9.8 / 8.2.3 Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to break into the 
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is affected
by various buffer overflow vulnerabilities that may allow an attacker
to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.2.3 or 4.9.8" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_summary(english:"Checks the remote BIND version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.(([0-1].*)|(2\.[0-2])).*"))security_hole(53);

if(ereg(string:vers,
    	pattern:"^4\.([0-8]|9\.[0-7]([^0-9]|$)).*"))security_hole(53);

