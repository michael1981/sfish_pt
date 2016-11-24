
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26108);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0845: libvorbis");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0845");
 script_set_attribute(attribute: "description", value: '
  Updated libvorbis packages to correct several security issues are now
  available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The libvorbis package contains runtime libraries for use in programs that
  support Ogg Voribs. Ogg Vorbis is a fully open, non-proprietary, patent-and
  royalty-free, general-purpose compressed audio format.

  Several flaws were found in the way libvorbis processed audio data. An
  attacker could create a carefully crafted OGG audio file in such a way that
  it could cause an application linked with libvorbis to crash or execute
  arbitrary code when it was opened. (CVE-2007-3106, CVE-2007-4029,
  CVE-2007-4065, CVE-2007-4066)

  Users of libvorbis are advised to upgrade to this updated package, which
  contains backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0845.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
script_summary(english: "Check for the version of the libvorbis packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libvorbis-1.1.2-3.el5.0", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvorbis-devel-1.1.2-3.el5.0", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvorbis-1.0-8.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvorbis-devel-1.0-8.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvorbis-1.1.0-2.el4.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvorbis-devel-1.1.0-2.el4.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
