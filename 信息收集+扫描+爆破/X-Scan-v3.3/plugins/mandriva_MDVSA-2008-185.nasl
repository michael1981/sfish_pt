
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37030);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:185: python-django");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:185 (python-django).");
 script_set_attribute(attribute: "description", value: "A cross-site request forgery vulnerability was discovered in Django
that, if exploited, could be used to perform unrequested deletion or
modification of data. Updated versions of Django will now discard
posts from users whose sessions have expired, so data will need to
be re-entered in these cases (CVE-2008-3909).
The versions of Django shipping with Mandriva Linux have been updated
to the latest patched versions that include the fix for this issue.
In addition, they provide other bug fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:185");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3909");
script_summary(english: "Check for the version of the python-django package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"python-django-0.95.4-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-0.95.4-0.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-0.96.3-0.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-0.96.3-0.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-0.96.3-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-0.96.3-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"python-django-", release:"MDK2007.1")
 || rpm_exists(rpm:"python-django-", release:"MDK2008.0")
 || rpm_exists(rpm:"python-django-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3909", value:TRUE);
}
exit(0, "Host is not affected");
