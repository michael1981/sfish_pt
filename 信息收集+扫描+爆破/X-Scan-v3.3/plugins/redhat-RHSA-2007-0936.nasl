
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26904);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0936: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0936");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a security issue in the Red Hat Enterprise
  Linux 5 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  A flaw was found in the IA32 system call emulation provided on AMD64 and
  Intel 64 platforms. An improperly validated 64-bit value could be stored in
  the %RAX register, which could trigger an out-of-bounds system call table
  access. An untrusted local user could exploit this flaw to run code in the
  kernel (ie a root privilege escalation). (CVE-2007-4573).

  Red Hat would like to thank Wojciech Purczynski for reporting this issue.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these packages,
  which contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0936.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4573");
script_summary(english: "Check for the version of the kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-8.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
