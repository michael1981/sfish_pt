
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12330);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-227:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-227");
 script_set_attribute(attribute: "description", value: '
  This kernel update for Red Hat Linux Advanced Server 2.1 addresses some
  security issues and provides minor bug fixes.

  The Linux kernel handles the basic functions of the operating system. A
  number of vulnerabilities were found in the Red Hat Linux Advanced Server
  kernel. These vulnerabilities could allow a local user to obtain elevated
  (root) privileges.

  The vulnerabilities existed in a number of drivers, including
  stradis, rio500, se401, apm, usbserial, and usbvideo.

  Additionally, a number of bugs have been fixed, and some small feature
  enhancements have been added.

  - Failed READA requests could be interpreted as I/O errors under high
  load on SMP; this has been fixed.

  - In rare cases, TLB entries could be corrupted on SMP Pentium IV
  systems; this potential for corruption has been fixed. Third-party modules
  will need to be recompiled to take advantage of these fixes.

  - The latest tg3 driver fixes have been included; the tg3 driver
  now supports more hardware.

  - A mechanism is provided to specify the location of core files and to
  set the name pattern to include the UID, program, hostname, and PID of
  the process that caused the core dump.

  A number of SCSI fixes have also been included:

  - Configure sparse LUNs in the qla2200 driver
  - Clean up erroneous accounting data as seen by /proc/partitions and iostat
  - Allow up to 128 scsi disks
  - Do not start logical units that require manual intervention, avoiding
  unnecessary startup delays
  - Improve SCSI layer throughput by properly clustering DMA requests

  All users of Red Hat Linux Advanced Server are advised to upgrade to the
  errata packages.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-227.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1572", "CVE-2002-1573");
script_summary(english: "Check for the version of the   kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"  kernel-2.4.9-e.9.athlon.rpm               700597b6bdcdb84b26b75fcf4102b070", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.9.athlon.rpm           7aac072909667beeff70d6768b760158", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
