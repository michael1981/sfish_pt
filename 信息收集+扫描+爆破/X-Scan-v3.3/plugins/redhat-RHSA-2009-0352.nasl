
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36099);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0352: gstreamer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0352");
 script_set_attribute(attribute: "description", value: '
  Updated gstreamer-plugins-base packages that fix a security issue are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GStreamer is a streaming media framework based on graphs of filters which
  operate on media data. GStreamer Base Plug-ins is a collection of
  well-maintained base plug-ins.

  An integer overflow flaw which caused a heap-based buffer overflow was
  discovered in the Vorbis comment tags reader. An attacker could create a
  carefully-crafted Vorbis file that would cause an application using
  GStreamer to crash or, potentially, execute arbitrary code if opened by a
  victim. (CVE-2009-0586)

  All users of gstreamer-plugins-base are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue. After
  installing this update, all applications using GStreamer (such as Totem or
  Rhythmbox) must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0352.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0586");
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

if ( rpm_check( reference:"gstreamer-plugins-base-0.10.20-3.0.1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gstreamer-plugins-base-devel-0.10.20-3.0.1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
