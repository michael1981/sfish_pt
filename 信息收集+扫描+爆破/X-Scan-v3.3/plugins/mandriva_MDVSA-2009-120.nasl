
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38864);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:120: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:120 (openssl).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed
in OpenSSL:
The dtls1_buffer_record function in ssl/d1_pkt.c in OpenSSL 0.9.8k
and earlier 0.9.8 versions allows remote attackers to cause a denial
of service (memory consumption) via a large series of future epoch
DTLS records that are buffered in a queue, aka DTLS record buffer
limitation bug. (CVE-2009-1377)
Multiple memory leaks in the dtls1_process_out_of_seq_message function
in ssl/d1_both.c in OpenSSL 0.9.8k and earlier 0.9.8 versions allow
remote attackers to cause a denial of service (memory consumption)
via DTLS records that (1) are duplicates or (2) have sequence numbers
much greater than current sequence numbers, aka DTLS fragment handling
memory leak. (CVE-2009-1378)
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:120");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1377", "CVE-2009-1378");
script_summary(english: "Check for the version of the openssl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libopenssl0.9.8-0.9.8g-4.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8g-4.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8g-4.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8g-4.4mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8h-3.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8h-3.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8h-3.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8h-3.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8k-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8k-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8k-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8k-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2008.1")
 || rpm_exists(rpm:"openssl-", release:"MDK2009.0")
 || rpm_exists(rpm:"openssl-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1377", value:TRUE);
 set_kb_item(name:"CVE-2009-1378", value:TRUE);
}
exit(0, "Host is not affected");
