#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(25499);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2007-0465");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2007-0465.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2007-0465.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:M/C:P/I:P/A:P");
script_end_attributes();

script_cve_id("CVE-2004-0813","CVE-2007-1716");

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

if ( rpm_check(reference:"pam-0.75-72", release:"CentOS-3", cpu:"ia64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"pam-devel-0.75-72", release:"CentOS-3", cpu:"ia64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdrecord-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdrecord-devel-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"mkisofs-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"pam-0.75-72", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"pam-devel-0.75-72", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdda2wav-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"i386") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdrecord-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdrecord-devel-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"mkisofs-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"pam-0.75-72", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"pam-devel-0.75-72", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"cdda2wav-2.01.0.a32-0.EL3.6", release:"CentOS-3", cpu:"x86_64") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
