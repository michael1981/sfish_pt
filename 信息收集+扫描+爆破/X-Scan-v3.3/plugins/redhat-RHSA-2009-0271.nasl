
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35617);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0271: gstreamer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0271");
 script_set_attribute(attribute: "description", value: '
  Updated gstreamer-plugins-good packages that fix several security issues
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GStreamer is a streaming media framework, based on graphs of filters which
  operate on media data. GStreamer Good Plug-ins is a collection of
  well-supported, GStreamer plug-ins of good quality released under the LGPL
  license.

  Multiple heap buffer overflows and an array indexing error were found in
  the GStreamer\'s QuickTime media file format decoding plugin. An attacker
  could create a carefully-crafted QuickTime media .mov file that would cause
  an application using GStreamer to crash or, potentially, execute arbitrary
  code if played by a victim. (CVE-2009-0386, CVE-2009-0387, CVE-2009-0397)

  All users of gstreamer-plugins-good are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues. After
  installing the update, all applications using GStreamer (such as totem or
  rhythmbox) must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0271.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
script_summary(english: "Check for the version of the gstreamer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gstreamer-plugins-good-0.10.9-1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-good-devel-0.10.9-1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
