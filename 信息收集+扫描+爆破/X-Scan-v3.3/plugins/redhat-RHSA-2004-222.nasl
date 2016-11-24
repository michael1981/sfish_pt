
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12499);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-222: arts");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-222");
 script_set_attribute(attribute: "description", value: '
  Updated kdelibs packages that fix telnet URI handler and mailto URI handler
  file vulnerabilities are now available.

  The kdelibs packages include libraries for the K Desktop Environment.

  KDE Libraries include: kdecore (KDE core library), kdeui (user interface),
  kfm (file manager), khtmlw (HTML widget), kio (Input/Output, networking),
  kspell (spelling checker), jscript (javascript), kab (addressbook), kimgio
  (image manipulation). Konqueror is a file manager and Web browser for the
  K Desktop Environment (KDE).

  iDEFENSE identified a vulnerability in the Opera web browser that could
  allow remote attackers to create or truncate arbitrary files. The KDE team
  has found two similar vulnerabilities that also exist in KDE.

  A flaw in the telnet URI handler may allow options to be passed to the
  telnet program, resulting in creation or replacement of files. An attacker
  could create a carefully crafted link such that when opened by a victim it
  creates or overwrites a file with the victim\'s permissions.

  A flaw in the mailto URI handler may allow options to be passed to the
  kmail program. These options could cause kmail to write to the file system
  or to run on a remote X display. An attacker could create a carefully
  crafted link in such a way that access may be obtained to run arbitrary
  code as the victim.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0411 to these issues.

  Note: Red Hat Enterprise Linux 2.1 is only vulnerable to the mailto URI
  flaw as a previous update shipped without a telnet.protocol file.

  All users of KDE are advised to upgrade to these erratum packages, which
  contain a backported patch for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-222.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0411");
script_summary(english: "Check for the version of the arts packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"arts-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1.3-6.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1.3-6.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
