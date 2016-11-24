
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2267
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35959);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2267: opensc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2267 (opensc)");
 script_set_attribute(attribute: "description", value: "OpenSC is a package for for accessing smart card devices.  Basic
functionality (e.g. SELECT FILE, READ BINARY) should work on any ISO
7816-4 compatible smart card.  Encryption and decryption using private
keys on the smart card is possible with PKCS #15 compatible cards,
such as the FINEID (Finnish Electronic IDentity) card.  Swedish Posten
eID cards have also been confirmed to work.

-
Update Information:

Security update fixing CVE-2008-3972, CVE-2008-2235, and CVE-2009-0368.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2235", "CVE-2008-3972", "CVE-2009-0368");
script_summary(english: "Check for the version of the opensc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"opensc-0.11.7-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
