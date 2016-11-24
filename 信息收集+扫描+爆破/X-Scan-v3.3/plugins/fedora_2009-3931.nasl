
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3931
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38673);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-3931: prelude-manager");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3931 (prelude-manager)");
 script_set_attribute(attribute: "description", value: "Prelude Manager is the main program of the Prelude Hybrid IDS
suite. It is a multithreaded server which handles connections from
the Prelude sensors. It is able to register local or remote
sensors, let the operator configure them remotely, receive alerts,
and store alerts in a database or any format supported by
reporting plugins, thus providing centralized logging and
analysis. It also provides relaying capabilities for failover and
replication. The IDMEF standard is used for alert representation.
Support for filtering plugins allows you to hook in different
places in the Manager to define custom criteria for alert relaying
and logging.

-
Update Information:

The configuration file of prelude-manager contains a database password and is
world readable. This update restricts permissions to the root account.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the prelude-manager package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"prelude-manager-0.9.14.2-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
