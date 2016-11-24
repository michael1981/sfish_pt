
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25984);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0539: aide");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0539");
 script_set_attribute(attribute: "description", value: '
  An updated aide package that fixes various bugs is now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Advanced Intrusion Detection Environment (AIDE) is a file integrity checker
  and intrusion detection program.

  A flaw was discovered in the way file checksums were stored in the AIDE
  database. A packaging flaw in the Red Hat AIDE rpm resulted in the file
  database not containing any file checksum information. This could prevent
  AIDE from detecting certain file modifications. (CVE-2007-3849)

  This update also fixes the following bugs:

  * certain configurations could result in a segmentation fault upon
  initialization.

  * AIDE was unable to open its log file in the LSPP evaluated configuration.

  * if AIDE found SELinux context differences, the changed files report it
  generated only included the first 32 characters of the context.

  All users of AIDE are advised to upgrade to this updated package containing
  AIDE version 0.13.1 which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0539.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3849");
script_summary(english: "Check for the version of the aide packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"aide-0.13.1-2.0.4.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
