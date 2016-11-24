
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12428);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-310: fileutils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-310");
 script_set_attribute(attribute: "description", value: '
  Updated fileutils packages that close a potential denial of service
  vulnerability are now available.

  The fileutils package contains several basic system utilities. One of
  these utilities is the "ls" program, which is used to list information
  about files and directories.

  Georgi Guninski discovered a memory starvation denial of service
  vulnerability in the ls program. It is possible to make ls allocate a
  huge amount of memory by specifying certain command line arguments. This
  vulnerability is remotely exploitable through services like wu-ftpd, which
  pass user arguments to ls. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2003-0854 to this issue.

  A non-exploitable integer overflow in ls has been discovered. It is
  possible to make ls crash by specifying certain command line arguments.
  This vulnerability is remotely exploitable through services like wu-ftpd,
  which pass user arguments to ls. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2003-0853 to this issue.

  Users are advised to update to these erratum packages, which contain
  backported security patches that correct these vulnerabilities.

  These packages also add support for the O_DIRECT flag, which controls the
  use of synchronous I/O on file systems such as OCFS.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-310.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0853", "CVE-2003-0854");
script_summary(english: "Check for the version of the fileutils packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fileutils-4.1-10.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
