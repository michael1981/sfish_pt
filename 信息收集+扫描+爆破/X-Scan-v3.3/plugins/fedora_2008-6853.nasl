
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6853
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33768);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6853: asterisk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6853 (asterisk)");
 script_set_attribute(attribute: "description", value: "Asterisk is a complete PBX in software. It runs on Linux and provides
all of the features you would expect from a PBX and more. Asterisk
does voice over IP in three protocols, and can interoperate with
almost all standards-based telephony equipment using relatively
inexpensive hardware.

-
Update Information:

Security fixes for CVE-2008-3263 / AST-2008-010 and CVE-2008-3264 /
AST-2008-011:    AST-2008-010: Asterisk IAX 'POKE' resource exhaustion  -
[9]http://downloads.digium.com/pub/security/AST-2008-010.html    AST-2008-011:
Traffic amplification in IAX2 firmware provisioning system  -
[10]http://downloads.digium.com/pub/security/AST-2008-011.html    Bugfixes:  -
Add
patch SVN patch for asterisk crash when used with LDAP backend (#442011)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3264");
script_summary(english: "Check for the version of the asterisk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"asterisk-1.6.0-0.19.beta9.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
