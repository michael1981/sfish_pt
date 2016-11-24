
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27567);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0975: flac");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0975");
 script_set_attribute(attribute: "description", value: '
  An updated flac package to correct a security issue is now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  FLAC is a Free Lossless Audio Codec. The flac package consists of a FLAC
  encoder and decoder in library form, a program to encode and decode FLAC
  files, a metadata editor for FLAC files and input plugins for various music
  players.

  A security flaw was found in the way flac processed audio data. An
  attacker could create a carefully crafted FLAC audio file in such a way that
  it could cause an application linked with flac libraries to crash or execute
  arbitrary code when it was opened. (CVE-2007-4619)

  Users of flac are advised to upgrade to this updated package, which
  contains a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0975.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4619", "CVE-2007-6277");
script_summary(english: "Check for the version of the flac packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"flac-1.1.2-28.el5_0.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flac-devel-1.1.2-28.el5_0.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flac-1.1.0-7.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"flac-devel-1.1.0-7.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xmms-flac-1.1.0-7.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
