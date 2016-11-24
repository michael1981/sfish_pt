
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21207);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:070: sash");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:070 (sash).");
 script_set_attribute(attribute: "description", value: "Tavis Ormandy of the Gentoo Security Project discovered a vulnerability
in zlib where a certain data stream would cause zlib to corrupt a data
structure, resulting in the linked application to dump core
(CVE-2005-2096).
Markus Oberhumber discovered additional ways that a specially-crafted
compressed stream could trigger an overflow. An attacker could create
such a stream that would cause a linked application to crash if opened
by a user (CVE-2005-1849).
Both of these issues have previously been fixed in zlib, but sash links
statically against zlib and is thus also affected by these issues. New
sash packages are available that link against the updated zlib packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:070");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1849", "CVE-2005-2096");
script_summary(english: "Check for the version of the sash package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sash-3.7-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sash-3.7-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sash-", release:"MDK10.2")
 || rpm_exists(rpm:"sash-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
exit(0, "Host is not affected");
