
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14123);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:024: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:024 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of serious issues have been discovered in versions of Ethereal
prior to 0.10.2. Stefan Esser discovered thirteen buffer overflows in
the NetFlow, IGAP, EIGRP, PGM, IrDA, BGP, ISUP, and TCAP dissectors.
Jonathan Heusser discovered that a carefully-crafted RADIUS packet
could cause Ethereal to crash. It was also found that a zero-length
Presentation protocol selector could make Ethereal crash. Finally, a
corrupt color filter file could cause a segmentation fault. It is
possible, through the exploitation of some of these vulnerabilities, to
cause Ethereal to crash or run arbitrary code by injecting a malicious,
malformed packet onto the wire, by convincing someone to read a
malformed packet trace file, or by creating a malformed color filter
file.
The updated packages bring Ethereal to version 0.10.3 which is not
vulnerable to these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:024");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0176", "CVE-2004-0365", "CVE-2004-0367");
script_summary(english: "Check for the version of the ethereal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.10.3-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.3-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0176", value:TRUE);
 set_kb_item(name:"CVE-2004-0365", value:TRUE);
 set_kb_item(name:"CVE-2004-0367", value:TRUE);
}
exit(0, "Host is not affected");
