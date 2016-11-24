
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42131);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:276: python-django");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:276 (python-django).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in python-django:
The Admin media handler in core/servers/basehttp.py in Django 1.0
and 0.96 does not properly map URL requests to expected static media
files, which allows remote attackers to conduct directory traversal
attacks and read arbitrary files via a crafted URL (CVE-2009-2659).
Algorithmic complexity vulnerability in the forms library in Django
1.0 before 1.0.4 and 1.1 before 1.1.1 allows remote attackers to cause
a denial of service (CPU consumption) via a crafted (1) EmailField
(email address) or (2) URLField (URL) that triggers a large amount
of backtracking in a regular expression (CVE-2009-3695).
The versions of Django shipping with Mandriva Linux have been updated
to the latest patched version that include the fix for this issue.
In addition, they provide other bug fixes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:276");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2659", "CVE-2009-3695");
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

if ( rpm_check( reference:"python-django-1.0.4-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-1.0.4-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-1.0.4-0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-django-1.0.4-0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"python-django-", release:"MDK2009.0")
 || rpm_exists(rpm:"python-django-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-2659", value:TRUE);
 set_kb_item(name:"CVE-2009-3695", value:TRUE);
}
exit(0, "Host is not affected");
