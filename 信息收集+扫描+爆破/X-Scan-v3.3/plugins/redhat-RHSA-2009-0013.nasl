
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35358);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0013: avahi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0013");
 script_set_attribute(attribute: "description", value: '
  Updated avahi packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Avahi is an implementation of the DNS Service Discovery and Multicast DNS
  specifications for Zeroconf Networking. It facilitates service discovery on
  a local network. Avahi and Avahi-aware applications allow you to plug your
  computer into a network and, with no configuration, view other people to
  chat with, see printers to print to, and find shared files on other computers.

  Hugo Dias discovered a denial of service flaw in avahi-daemon. A remote
  attacker on the same local area network (LAN) could send a
  specially-crafted mDNS (Multicast DNS) packet that would cause avahi-daemon
  to exit unexpectedly due to a failed assertion check. (CVE-2008-5081)

  All users are advised to upgrade to these updated packages, which contain a
  backported patch which resolves this issue. After installing the update,
  avahi-daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0013.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5081");
script_summary(english: "Check for the version of the avahi packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"avahi-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-compat-howl-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-compat-howl-devel-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-compat-libdns_sd-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-compat-libdns_sd-devel-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-devel-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-glib-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-glib-devel-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-qt3-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-qt3-devel-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"avahi-tools-0.6.16-1.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
