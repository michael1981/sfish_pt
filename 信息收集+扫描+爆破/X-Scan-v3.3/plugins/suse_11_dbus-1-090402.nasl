
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41382);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  dbus-1 (2009-04-02)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for dbus-1");
 script_set_attribute(attribute: "description", value: "The dbus package used a too permissive configuration.
Therefore intended access control for some services was not
applied (CVE-2008-4311).

The new configuration denies access by default. Some dbus
services may break due to this setting and need an updated
configuration as well.

With the previous update wireless networking didn't work
anymore on some machines due to stale files in
/var/run/dbus/at_console. The dbus init script now cleans
up that directory on boot.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for dbus-1");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=443307");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=486267");
script_end_attributes();

 script_cve_id("CVE-2008-4311");
script_summary(english: "Check for the dbus-1 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"dbus-1-1.2.10-3.9.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"dbus-1-1.2.10-3.9.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
