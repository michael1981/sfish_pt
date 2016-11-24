
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-4928
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38993);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-4928: mingw32-opensc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-4928 (mingw32-opensc)");
 script_set_attribute(attribute: "description", value: "OpenSC is a package for for accessing smart card devices.  Basic
functionality (e.g. SELECT FILE, READ BINARY) should work on any ISO
7816-4 compatible smart card.  Encryption and decryption using private
keys on the smart card is possible with PKCS #15 compatible cards,
such as the FINEID (Finnish Electronic IDentity) card.  Swedish Posten
eID cards have also been confirmed to work.

This is the MinGW cross-compiled Windows library.

-
Update Information:

CVE-2009-1603    A minor update fixing security problem within pkcs11-tool
command.    [9]http://www.opensc-project.org/pipermail/opensc-
announce/2009-May/000025.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1603");
script_summary(english: "Check for the version of the mingw32-opensc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mingw32-opensc-0.11.8-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
