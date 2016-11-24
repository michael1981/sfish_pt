#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(21997);
 script_version("$Revision: 1.7 $");
 script_name(english:"CentOS : RHSA-2006-0493");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0493.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2006-0493.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_end_attributes();

script_cve_id("CVE-2005-2973","CVE-2005-3272","CVE-2005-3359","CVE-2006-0555","CVE-2006-0741","CVE-2006-0744","CVE-2006-1522","CVE-2006-1525","CVE-2006-1527","CVE-2006-1528","CVE-2006-1855","CVE-2006-1856","CVE-2006-1862","CVE-2006-1864","CVE-2006-2271","CVE-2006-2272","CVE-2006-2274");

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

if ( rpm_check(reference:"kernel-doc-2.6.9-34.0.1.EL", release:"CentOS-4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-largesmp-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-largesmp-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-largesmp-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-largesmp-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-34.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
