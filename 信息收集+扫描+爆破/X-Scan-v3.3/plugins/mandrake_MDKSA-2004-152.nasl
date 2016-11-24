
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16014);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:152: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:152 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in Ethereal:
- Matthew Bing discovered a bug in DICOM dissection that could make
Ethereal crash (CVE-2004-1139)
- An invalid RTP timestamp could make Ethereal hang and create a large
temporary file, possibly filling available disk space (CVE-2004-1140)
- The HTTP dissector could access previously-freed memory, causing a
crash (CVE-2004-1141)
- Brian Caswell discovered that an improperly formatted SMB packet
could make Ethereal hang, maximizing CPU utilization (CVE-2004-1142)
Ethereal 0.10.8 was released to correct these problems and is being
provided.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:152");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1139", "CVE-2004-1140", "CVE-2004-1141", "CVE-2004-1142");
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

if ( rpm_check( reference:"ethereal-0.10.8-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.8-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.0")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1139", value:TRUE);
 set_kb_item(name:"CVE-2004-1140", value:TRUE);
 set_kb_item(name:"CVE-2004-1141", value:TRUE);
 set_kb_item(name:"CVE-2004-1142", value:TRUE);
}
exit(0, "Host is not affected");
