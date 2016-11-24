#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(21967);
 script_version("$Revision: 1.6 $");
 script_name(english:"CentOS : RHSA-2005-808");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2005-808.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2005-808.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_end_attributes();

script_cve_id("CVE-2005-3053","CVE-2005-3108","CVE-2005-3110","CVE-2005-3119","CVE-2005-3180","CVE-2005-3181");

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

if ( rpm_check(reference:"kernel-doc-2.6.9-22.0.1.EL", release:"CentOS-4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-doc-2.6.9-22.0.1.106.unsupported", release:"CentOS-4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i586") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"i686") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.1.106.unsupported", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
