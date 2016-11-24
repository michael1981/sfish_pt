
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42091);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:263: sympa");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:263 (sympa).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in sympa:
sympa.pl in sympa 5.3.4 allows local users to overwrite arbitrary
files via a symlink attack on a temporary file. NOTE: wwsympa.fcgi
was also reported, but the issue occurred in a dead function, so it
is not a vulnerability (CVE-2008-4476).
This update fixes this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:263");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4476");
script_summary(english: "Check for the version of the sympa package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sympa-5.3.4-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sympa-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-4476", value:TRUE);
}
exit(0, "Host is not affected");
