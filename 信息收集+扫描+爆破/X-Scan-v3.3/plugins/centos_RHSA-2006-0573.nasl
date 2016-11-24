#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(21906);
 script_version("$Revision: 1.7 $");
 script_name(english:"CentOS : RHSA-2006-0573");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0573.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2006-0573.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_end_attributes();

script_cve_id("CVE-2006-2198","CVE-2006-2199","CVE-2006-3117");

 script_summary(english:"Checks for missing updates on the remote CentOS system");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2009 Tenable Network Security, Inc.");
 script_family(english:"CentOS Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/CentOS/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/CentOS/rpm-list") ) exit(1, "Could not obtain the list of packages");

if ( rpm_check(reference:"openoffice.org-1.1.2-34.6.0.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-kde-1.1.2-34.6.0.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-i18n-1.1.2-34.6.0.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-libs-1.1.2-34.6.0.EL4", release:"CentOS-4", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-1.1.2-34.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-i18n-1.1.2-34.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"openoffice.org-libs-1.1.2-34.2.0.EL3", release:"CentOS-3", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
