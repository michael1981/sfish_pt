
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12413);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-246: wu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-246");
 script_set_attribute(attribute: "description", value: '
  Updated wu-ftpd packages are available that fix an off-by-one buffer
  overflow.

  The wu-ftpd package contains the Washington University FTP (File Transfer
  Protocol) server daemon. FTP is a method of transferring files between
  machines.

  An off-by-one bug has been discovered in versions of wu-ftpd up to and
  including 2.6.2. On a vulnerable system, a remote attacker would be able
  to exploit this bug to gain root privileges.

  Red Hat Enterprise Linux contains a version of wu-ftpd that is affected by
  this bug, although it is believed that this issue will not be remotely
  exploitable due to compiler padding of the buffer that is the target of the
  overflow. However, Red Hat still advises that all users of wu-ftpd upgrade
  to these erratum packages, which contain a security patch.

  Red Hat would like to thank Wojciech Purczynski and Janusz Niewiadomski of
  ISEC Security Research for their responsible disclosure of this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-246.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0466");
script_summary(english: "Check for the version of the wu packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wu-ftpd-2.6.1-21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
