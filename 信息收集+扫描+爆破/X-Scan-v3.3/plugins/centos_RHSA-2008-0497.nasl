#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(33258);
 script_version("$Revision: 1.2 $");
 script_name(english:"CentOS : RHSA-2008-0497");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2008-0497.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2008-0497.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_end_attributes();

script_cve_id("CVE-2008-1951");

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

if ( rpm_check(reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-devel-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-provider-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-test-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-testsuite-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-wbemcli-1.5.1-13a.el4_6.1", release:"CentOS-4", cpu:"x86_64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-devel-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-test-1.5.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-devel-1.0.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-test-1.4.3-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-devel-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-test-1.3.7-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-1.0.13-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-1.0.11-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-test-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-1.1.8-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-test-1.1.8-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-0.7.9-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-test-0.7.9-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-devel-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-provider-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-test-2.1.1-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-testsuite-1.2.4-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-wbemcli-1.5.1-13a.el4_6.1", release:"CentOS-4", cpu:"i386") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-1.5.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-devel-1.5.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-base-test-1.5.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-devel-1.0.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-1.4.3-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-devel-1.4.3-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-fsvol-test-1.4.3-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-1.3.7-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-devel-1.3.7-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-network-test-1.3.7-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-1.0.13-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv3-test-1.0.13-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-1.0.11-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-nfsv4-test-1.0.11-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-1.2.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-params-test-1.2.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-1.1.8-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-sysfs-test-1.1.8-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-0.7.9-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-cmpi-syslog-test-0.7.9-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-2.1.1-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-devel-2.1.1-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-provider-2.1.1-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-gather-test-2.1.1-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-testsuite-1.2.4-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"sblim-wbemcli-1.5.1-13a.c4.1", release:"CentOS-4", cpu:"ia64") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
