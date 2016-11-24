
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27167);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  bind: Securityupdate to fix remote denial attack. (bind-2529)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch bind-2529");
 script_set_attribute(attribute: "description", value: "A security problem was fixed in the ISC BIND nameserver
version 9.3.4, these are addressed by this security update.

If recursion is enabled, a remote attacker can dereference
a freed fetch context causing the daemon to abort / crash.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch bind-2529");
script_end_attributes();

script_summary(english: "Check for the bind-2529 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"bind-9.3.2-56.1", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-9.3.2-56.1", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-32bit-9.3.2-56.1", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-libs-64bit-9.3.2-56.1", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"bind-utils-9.3.2-56.1", release:"SUSE10.2") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
