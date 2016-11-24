
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16147);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-014: nfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-014");
 script_set_attribute(attribute: "description", value: '
  An updated nfs-utils package that fixes various security issues is now
  available.

  The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  SGI reported that the statd daemon did not properly handle the SIGPIPE
  signal. A misconfigured or malicious peer could cause statd to crash,
  leading to a denial of service. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1014 to this issue.

  Arjan van de Ven discovered a buffer overflow in rquotad. On 64-bit
  architectures, an improper integer conversion can lead to a buffer
  overflow. An attacker with access to an NFS share could send a specially
  crafted request which could lead to the execution of arbitrary code. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0946 to this issue.

  All users of nfs-utils should upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-014.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0946", "CVE-2004-1014");
script_summary(english: "Check for the version of the nfs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nfs-utils-0.3.3-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
