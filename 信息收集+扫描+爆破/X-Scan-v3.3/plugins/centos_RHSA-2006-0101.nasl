#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(21977);
 script_version("$Revision: 1.7 $");
 script_name(english:"CentOS : RHSA-2006-0101");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2006-0101.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2006-0101.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_end_attributes();

script_cve_id("CVE-2002-2185","CVE-2004-1190","CVE-2005-2458","CVE-2005-2709","CVE-2005-2800","CVE-2005-3044","CVE-2005-3106","CVE-2005-3109","CVE-2005-3276","CVE-2005-3356","CVE-2005-3358","CVE-2005-3784","CVE-2005-3806","CVE-2005-3848","CVE-2005-3857","CVE-2005-3858","CVE-2005-4605");

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

if ( rpm_check(reference:"kernel-doc-2.6.9-22.0.2.EL", release:"CentOS-4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-hugemem-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i586") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-smp-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"kernel-devel-2.6.9-22.0.2.EL", release:"CentOS-4", cpu:"ia64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
