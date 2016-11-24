
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27153);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  AppArmor: Security Update to fix LD_PRELOAD and mmap-exec problems. (apparmor-1842)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apparmor-1842");
 script_set_attribute(attribute: "description", value: "This update fixes security problems in the AppArmor
confinment technology.

Since it adds new flags to the profile syntax, you likely
should review and adapt your profiles.

- If a profile allowed unconfined execution ('ux') of a
  child binary it was possible to inject code via
  LD_PRELOAD or similar environment variables into this
  child binary and execute code without confiment.

  We have added new flag 'Ux' (and 'Px' for 'px') which
makes the executed child clear the most critical
environment variables (similar to setuid programs). Special
care needs to be taken nevertheless that this interaction
between parent and child programs can not be exploited in
other ways to gain the rights of the child process.

- If a resource is marked as 'r' in the profile it was
  possible to use mmap with PROT_EXEC flag set to load this
  resource as executable piece of code, making it
  effectively 'ix'.

  This could be used by a coordinated attack between two
applications to potentially inject code into the reader.

  To allow mmap() executable access, supply the 'm' flag to
the applications profile.

Please also review the updated documentation.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch apparmor-1842");
script_end_attributes();

script_summary(english: "Check for the apparmor-1842 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apparmor-admin_en-10-7.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apparmor-docs-2.0-17.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apparmor-parser-2.0-21.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apparmor-profiles-2.0-34.9", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apparmor-utils-2.0-23.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"audit-1.1.3-23.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"audit-devel-1.1.3-23.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"audit-libs-1.1.3-23.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"yast2-apparmor-2.0-27.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
