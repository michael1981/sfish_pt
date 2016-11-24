
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-4892
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38959);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-4892: opensc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-4892 (opensc)");
 script_set_attribute(attribute: "description", value: "OpenSC is a package for for accessing smart card devices.  Basic
functionality (e.g. SELECT FILE, READ BINARY) should work on any ISO
7816-4 compatible smart card.  Encryption and decryption using private
keys on the smart card is possible with PKCS #15 compatible cards,
such as the FINEID (Finnish Electronic IDentity) card.  Swedish Posten
eID cards have also been confirmed to work.

-
Update Information:

A minor update fixing security problem within pkcs11-tool command.    [9]http:/
/www
.opensc-project.org/pipermail/opensc-announce/2009-May/000025.html
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the opensc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"opensc-0.11.8-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
