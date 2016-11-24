
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22220);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0393: ntp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0393");
 script_set_attribute(attribute: "description", value: '
  Updated ntp packages that fix several bugs are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The Network Time Protocol (NTP) is used to synchronize a computer\'s time
  with a reference time source.

  The NTP daemon (ntpd), when run with the -u option and using a string to
  specify the group, uses the group ID of the user instead of the group,
  which causes ntpd to run with different privileges than intended.
  (CVE-2005-2496)

  The following issues have also been addressed in this update:
  - The init script had several problems
  - The script executed on upgrade could fail
  - The man page for ntpd indicated the wrong option for specifying a chroot
  directory
  - The ntp daemon could crash with the message "Exiting: No more memory!"
  - There is a new option for syncing the hardware clock after a successful
  run of ntpdate

  Users of ntp should upgrade to these updated packages, which resolve these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0393.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2496");
script_summary(english: "Check for the version of the ntp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ntp-4.2.0.a.20040617-4.EL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
