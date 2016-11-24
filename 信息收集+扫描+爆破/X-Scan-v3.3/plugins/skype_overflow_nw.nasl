#
# (C) Tenable Network Security, Inc.
#


# This script depends on a .nbin plugin
if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
 script_id(21209);
 script_version("$Revision: 1.7 $");

 script_cve_id("CVE-2005-3265", "CVE-2005-3267");
 script_bugtraq_id(15190, 15192);
 script_xref(name:"OSVDB", value:"20306");
 script_xref(name:"OSVDB", value:"20307");
 script_xref(name:"OSVDB", value:"20308");

 script_name(english:"Skype < 1.4.0.84 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Skype, a peer-to-peer voice over IP
software. 

The remote version of this software is vulnerable to a heap overflow
in the handling of its data structures.  An attacker can exploit this
flaw by sending a specially-crafted network packet to UDP or TCP ports
Skype is listening on. A successful exploitation of this flaw will 
result in code execution on the remote host. 

In addition, Skype has been reported to contain overflows in the
handling of VCards and callto/skype URLs. However, Nessus has not
checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.skype.com/security/skype-sb-2005-03.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to skype version 1.4.0.84 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks for Skype Heap overflow for Windows");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 script_dependencies("skype_version.nbin");
 script_require_keys("Services/skype");

 exit(0);
}



port = get_kb_item("Services/skype");
if ( ! port ) exit(0);

ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if ( ! ts ) exit(0);

if ( ts < 510211313 ) security_hole( port );
