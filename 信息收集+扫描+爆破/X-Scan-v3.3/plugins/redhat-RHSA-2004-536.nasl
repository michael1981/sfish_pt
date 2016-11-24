
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15959);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-536: ncompress");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-536");
 script_set_attribute(attribute: "description", value: '
  An updated ncompress package that fixes a buffer overflow and problem in
  the handling of files larger than 2 GB is now available.

  The ncompress package contains the compress and uncompress file compression
  and decompression utilities, which are compatible with the original UNIX
  compress utility (.Z file extensions).

  A bug in the way ncompress handles long filenames has been discovered.
  ncompress versions 4.2.4 and earlier contain a stack based buffer overflow
  when handling very long filenames. It is possible that an attacker could
  execute arbitrary code on a victims machine by tricking the user into
  decompressing a carefully crafted filename. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2001-1413 to
  this issue.

  This updated ncompress package also fixes a problem in the handling of
  files larger than 2 GB.

  All users of ncompress should upgrade to this updated package, which
  contains fixes for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-536.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2001-1413");
script_summary(english: "Check for the version of the ncompress packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ncompress-4.2.4-37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
