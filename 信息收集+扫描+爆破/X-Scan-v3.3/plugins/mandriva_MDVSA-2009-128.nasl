
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39316);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:128: libmodplug");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:128 (libmodplug).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed
in libmodplug:
Integer overflow in the CSoundFile::ReadMed function (src/load_med.cpp)
in libmodplug before 0.8.6, as used in gstreamer-plugins and other
products, allows context-dependent attackers to execute arbitrary
code via a MED file with a crafted (1) song comment or (2) song name,
which triggers a heap-based buffer overflow (CVE-2009-1438).
Buffer overflow in the PATinst function in src/load_pat.cpp in
libmodplug before 0.8.7 allows user-assisted remote attackers to
cause a denial of service and possibly execute arbitrary code via a
long instrument name (CVE-2009-1513).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:128");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1438", "CVE-2009-1513");
script_summary(english: "Check for the version of the libmodplug package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmodplug0-0.8.4-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug0-devel-0.8.4-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug0-0.8.4-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug0-devel-0.8.4-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug0-0.8.6-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmodplug-devel-0.8.6-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libmodplug-", release:"MDK2008.1")
 || rpm_exists(rpm:"libmodplug-", release:"MDK2009.0")
 || rpm_exists(rpm:"libmodplug-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1438", value:TRUE);
 set_kb_item(name:"CVE-2009-1513", value:TRUE);
}
exit(0, "Host is not affected");
