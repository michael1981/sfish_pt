
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20361);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-864: udev");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-864");
 script_set_attribute(attribute: "description", value: '
  Updated udev packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The udev package contains an implementation of devfs in userspace using
  sysfs and /sbin/hotplug.

  Richard Cunningham discovered a flaw in the way udev sets permissions on
  various files in /dev/input. It may be possible for an authenticated
  attacker to gather sensitive data entered by a user at the console, such as
  passwords. The Common Vulnerabilities and Exposures project has assigned
  the name CVE-2005-3631 to this issue.

  All users of udev should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-864.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3631");
script_summary(english: "Check for the version of the udev packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"udev-039-10.10.EL4.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
