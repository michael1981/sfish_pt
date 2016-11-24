
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40596);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:202: memcached");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:202 (memcached).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in memcached:
Multiple integer overflows in memcached 1.1.12 and 1.2.2 allow remote
attackers to execute arbitrary code via vectors involving length
attributes that trigger heap-based buffer overflows (CVE-2009-2415).
This update provides a solution to this vulnerability. Additionally
memcached-1.2.x has been upgraded to 1.2.8 for 2009.0/2009.1 and MES
5 that contains a number of upstream fixes, the repcached patch has
been upgraded to 2.2 as well.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:202");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2415");
script_summary(english: "Check for the version of the memcached package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"memcached-1.2.8-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"memcached-1.2.8-0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"memcached-", release:"MDK2009.0")
 || rpm_exists(rpm:"memcached-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-2415", value:TRUE);
}
exit(0, "Host is not affected");
