
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37368);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:088: clamav");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:088 (clamav).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities were discovered in ClamAV and corrected with
the 0.93 release, including:
ClamAV 0.92 allowed local users to overwrite arbitrary files via
a symlink attack on temporary files or on .ascii files in sigtool,
when utf16-decode is enabled (CVE-2007-6595).
ClamAV 0.92 did not recognize Base64 uuencoded archives, which allowed
remoted attackers to bypass the sanner via a base64-uuencoded file
(CVE-2007-6596).
A heap-based buffer overflow in ClamAV 0.92.1 allowed remote attackers
to execute arbitrary code via a crafted PeSpin packed PE binary
(CVE-2008-0314).
An integer overflow in libclamav prior to 0.92.1 allowed remote
attackers to cause a denial of service and possibly execute arbitrary
code via a crafted Petite packed PE file, which triggered a heap-based
buffer overflow (CVE-2008-0318).
An unspecified vulnerability in ClamAV prior to 0.92.1 triggered heap
corruption (CVE-2008-0728).
A buffer overflow in ClamAV 0.92 and 0.92.1 allowed remote attackers
to execute arbitrary code via a crafted Upack PE file (CVE-2008-1100).
ClamAV prior to 0.93 allowed remote attackers to cause a denial of
service (CPU consumption) via a crafted ARJ archive (CVE-2008-1387).
A heap-based buffer overflow in ClamAV 0.92.1 allowed remote attackers
to execute arbitrary code via a crafted WWPack compressed PE binary
(CVE-2008-1833).
ClamAV prior to 0.93 allowed remote attackers to bypass the scanning
engine via a RAR file with an invalid version number (CVE-2008-1835).
A vulnerability in rfc2231 handling in ClamAV prior to 0.93 allowed
remote attackers to cause a denial of service (crash) via a crafted
message that produced a string that was not null terminated, triggering
a buffer over-read (CVE-2008-1836).
A vulnerability in libclamunrar in ClamAV prior to 0.93 allowed remote
attackers to cause a denial of service (crash) via a crafted RAR file
(CVE-2008-1837).
Other bugs have also been corrected in 0.93 which is being provided
with this update. Because this new version has increased the major
of the libclamav library, updated dependent packages are also being
provided.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:088");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6595", "CVE-2007-6596", "CVE-2008-0314", "CVE-2008-0318", "CVE-2008-0728", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-1833", "CVE-2008-1835", "CVE-2008-1836", "CVE-2008-1837");
script_summary(english: "Check for the version of the clamav package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"clamav-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamd-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamdmon-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav4-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav-devel-0.93-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamd-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamdmon-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"klamav-0.42-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav4-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav-devel-0.93-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamd-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"clamdmon-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dansguardian-2.9.9.2-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"klamav-0.42-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav4-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libclamav-devel-0.93-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK2007.1")
 || rpm_exists(rpm:"clamav-", release:"MDK2008.0")
 || rpm_exists(rpm:"clamav-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2007-6595", value:TRUE);
 set_kb_item(name:"CVE-2007-6596", value:TRUE);
 set_kb_item(name:"CVE-2008-0314", value:TRUE);
 set_kb_item(name:"CVE-2008-0318", value:TRUE);
 set_kb_item(name:"CVE-2008-0728", value:TRUE);
 set_kb_item(name:"CVE-2008-1100", value:TRUE);
 set_kb_item(name:"CVE-2008-1387", value:TRUE);
 set_kb_item(name:"CVE-2008-1833", value:TRUE);
 set_kb_item(name:"CVE-2008-1835", value:TRUE);
 set_kb_item(name:"CVE-2008-1836", value:TRUE);
 set_kb_item(name:"CVE-2008-1837", value:TRUE);
}
exit(0, "Host is not affected");
