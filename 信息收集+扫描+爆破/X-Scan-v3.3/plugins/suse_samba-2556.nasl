
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29575);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for samba (samba-2556)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch samba-2556");
 script_set_attribute(attribute: "description", value: "A logic error in the deferred open code can lead to an
infinite loop in Samba's smbd daemon (CVE-2007-0452).

In addition the following changes are included with these
packages:

- Move tdb utils to the client package.
- The version string of binaries reported by the -V option
  now include the package version control system version
  number.
- Fix time value reporting in libsmbclient; [#195285].
- Store and restore NT hashes as string compatible values;
  [#185053].
- Added winbindd null sid fix; [#185053].
- Fix from Alison Winters of SGI to build even if
  make_vscan is 0.
- Send correct workstation name to prevent
  NT_STATUS_INVALID_WORKSTATION beeing returned in
  samlogon; [#148645], [#161051].
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch samba-2556");
script_end_attributes();

script_cve_id("CVE-2007-0452");
script_summary(english: "Check for the samba-2556 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"samba-3.0.22-13.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.22-13.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.22-13.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-3.0.22-13.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.22-13.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.22-13.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
