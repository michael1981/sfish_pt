#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10882);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2001-0361");
 script_bugtraq_id(2344);
 script_xref(name:"OSVDB", value:"2116");
 
 script_name(english:"SSH Protocol Version 1 Session Key Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service offers an insecure cryptographic protocol." );
 script_set_attribute(attribute:"description", value:
"The remote SSH daemon supports connections made using the version 1.33
and/or 1.5 of the SSH protocol. 

These protocols are not completely cryptographically safe so they
should not be used." );
 script_set_attribute(attribute:"solution", value:
"Disable compatibility with version 1 of the protocol." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Negotiate SSH connections");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("ssh_proto_version.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


port = get_kb_item("Services/ssh");
if(!port)port = 22;

if (  get_kb_item("SSH/" + port + "/v1_supported" ) )
	security_warning(port);
