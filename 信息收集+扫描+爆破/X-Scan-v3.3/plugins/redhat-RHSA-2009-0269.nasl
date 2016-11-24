
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35615);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0269: gstreamer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0269");
 script_set_attribute(attribute: "description", value: '
  Updated gstreamer-plugins packages that fix one security issue are now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The gstreamer-plugins package contains plug-ins used by the GStreamer
  streaming-media framework to support a wide variety of media types.

  An array indexing error was found in the GStreamer\'s QuickTime media file
  format decoding plug-in. An attacker could create a carefully-crafted
  QuickTime media .mov file that would cause an application using GStreamer
  to crash or, potentially, execute arbitrary code if played by a victim.
  (CVE-2009-0398)

  All users of gstreamer-plugins are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue. After
  installing the update, all applications using GStreamer (such as
  nautilus-media) must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0269.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0398");
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

if ( rpm_check( reference:"gstreamer-plugins-0.6.0-19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-devel-0.6.0-19", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
