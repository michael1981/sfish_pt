#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11857);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0029");
 script_bugtraq_id(6186);
 script_xref(name:"OSVDB", value:"8330");
 script_xref(name:"IAVA", value:"2002-A-0012");
 
 script_name(english:"ISC BIND < 4.9.11 stub resolver (libresolv.a) DNS Response Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND 4.x server, according to its version number, is vulnerable 
to a buffer overflow in the DNS stub resolver library.

An attacker might use this flaw to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 4.9.11 or later in the 4.x branch, or consider upgrading 
to a more recent release." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


 script_end_attributes();
 
 script_summary(english:"Checks that BIND is not version 4.9.2 through 4.9.10");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if (vers =~ "^4\.9\.[2-9]") security_hole(53); 
if (vers =~ "^4\.9\.10") security_hole(53);


