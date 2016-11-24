
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38683);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:105: memcached");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:105 (memcached).");
 script_set_attribute(attribute: "description", value: "The process_stat function in Memcached prior 1.2.8 discloses
memory-allocation statistics in response to a stats malloc command,
which allows remote attackers to obtain potentially sensitive
information by sending this command to the daemon's TCP port
(CVE-2009-1255, CVE-2009-1494).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:105");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1255", "CVE-2009-1494");
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

if ( rpm_check( reference:"memcached-1.2.6-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"memcached-1.2.6-4.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"memcached-", release:"MDK2009.0")
 || rpm_exists(rpm:"memcached-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1255", value:TRUE);
 set_kb_item(name:"CVE-2009-1494", value:TRUE);
}
exit(0, "Host is not affected");
