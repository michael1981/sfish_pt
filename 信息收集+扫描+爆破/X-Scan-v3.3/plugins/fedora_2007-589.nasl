
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-589
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25510);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 5 2007-589: iscsi-initiator-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-589 (iscsi-initiator-utils)");
 script_set_attribute(attribute: "description", value: "The iscsi package provides the server daemon for the iSCSI protocol,
as well as the utility programs used to manage it. iSCSI is a protocol
for distributed disk access using SCSI commands sent over Internet
Protocol networks.

Update Information:

This update to iscsi-initiator-utils is a rebase to the
upstream open-iscsi-2.0-865 release. This release includes
two security fixes which are described here
[8]https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=243719
bug fixes and new features.

The tools in this release use a different db format than
past releases, but the tools are able to read old and new
formats. If you want to use the new features you must update
the db, by rediscovering your targets and reconfiguring
them. Once the db has been updated you cannot use older
tools on it.

See the README and man pages for information on the new
features.

This release requires that kernel 2.6.18 or newer be used.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the iscsi-initiator-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"iscsi-initiator-utils-5.2.0.865-0.0.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
