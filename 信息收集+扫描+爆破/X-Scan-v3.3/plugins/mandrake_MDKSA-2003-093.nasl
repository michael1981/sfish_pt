
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14075);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:093: gtkhtml");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:093 (gtkhtml).");
 script_set_attribute(attribute: "description", value: "Alan Cox discovered that certain malformed messages could cause the
Evolution mail component to crash due to a null pointer dereference in
the GtkHTML library, versions prior to 1.1.0.
The updated package provides a patched version of GtkHTML; versions of
Mandrake Linux more recent than 9.0 do not require this fix as they
already come with version 1.1.0.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:093");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0541");
script_summary(english: "Check for the version of the gtkhtml package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libgtkhtml20-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtkhtml20-devel-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gtkhtml-1.0.4-4.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gtkhtml-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0541", value:TRUE);
}
exit(0, "Host is not affected");
