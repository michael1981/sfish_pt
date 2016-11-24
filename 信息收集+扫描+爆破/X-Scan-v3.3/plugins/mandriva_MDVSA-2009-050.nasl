
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38149);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:050-1: python-pycrypto");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:050-1 (python-pycrypto).");
 script_set_attribute(attribute: "description", value: "A vulnerability have been discovered and corrected in PyCrypto
ARC2 module 2.0.1, which allows remote attackers to cause a denial
of service and possibly execute arbitrary code via a large ARC2 key
length (CVE-2009-0544).
The updated packages have been patched to prevent this.
Update:
The previous update package was not signed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:050-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0544");
script_summary(english: "Check for the version of the python-pycrypto package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"python-pycrypto-2.0.1-4.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"python-pycrypto-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0544", value:TRUE);
}
exit(0, "Host is not affected");
