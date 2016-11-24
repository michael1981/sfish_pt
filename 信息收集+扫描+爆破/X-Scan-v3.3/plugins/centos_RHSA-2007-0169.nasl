#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if ( description )
{
 script_id(25126);
 script_version("$Revision: 1.4 $");
 script_name(english:"CentOS : RHSA-2007-0169");
 script_set_attribute(attribute: "synopsis", value: "The remote host is missing a security update.");
 script_set_attribute(attribute: "description", value: 
"The remote CentOS system is missing a security update which has been 
documented in Red Hat advisory RHSA-2007-0169.");
 script_set_attribute(attribute: "see_also", value:
"https://rhn.redhat.com/errata/RHSA-2007-0169.html");
 script_set_attribute(attribute: "solution", value:
"Upgrade to the newest packages by doing :

  yum update");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_end_attributes();

script_cve_id("CVE-2007-0771","CVE-2007-1000","CVE-2007-1388");

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

if ( rpm_check(reference:"892e3c6a2a025403264d8dd6d68552f4 kernel-doc-2.6.18-8.1.3.el5", release:"CentOS-5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"326e8de03115a7134c6bea14e47ebefb  kernel-doc-2.6.18-8.1.3.el5", release:"CentOS-5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"48baeb09320670e11512e214b061b1b4 kernel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"a36b926288ebe4122042cbda5ec4ecb3 kernel-devel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"c29cfe576eb2cb1e2372c025a441ff4a kernel-headers-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"2e02d7d015332ce7948d74532b43c60b kernel-xen-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"Kernel-xen-devel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"x86_64") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"c015c981879a895f5053cf229f0460ce  kernel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"9c7232573c65adf0254a6156e9699076  kernel-devel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"a0d23dc6af2084bd30a3c9e03a954f13  kernel-headers-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i386") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"24bc96e9da2dd8f416f0a21753e7e8a2  kernel-PAE-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"bed52bc59ae7dcd85f2de61fdbb7d386  kernel-PAE-devel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"979fdefbe9861fb1481ec82b8c725f95  kernel-xen-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check(reference:"deb668f591bebf60a62c099be9654d79  kernel-xen-devel-2.6.18-8.1.3.el5", release:"CentOS-5", cpu:"i686") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
