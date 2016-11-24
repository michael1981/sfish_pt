
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29574);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for Samba (samba-1961)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch samba-1961");
 script_set_attribute(attribute: "description", value: "- Fix pam config file parsing in pam_winbind; bso [#3916].
- Prevent potential crash in winbindd's credential cache
  handling; [#184450].
- Fix memory exhaustion DoS; CVE-2006-3403; [#190468].
- Fix the munlock call, samba.org svn rev r16755 from
  Volker.
- Change the kerberos principal for LDAP authentication to
  netbios-name$@realm from host/name@realm; [#184450].
- Ensure to link all required libraries to libnss_wins;
  [#184306].
- Change log level of debug message to avaoid flodded nmbd
  log; [#157623].
- Add 'usershare allow guests = Yes' to the default config;
  [#144787].
- Fix syntax error in configure script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch samba-1961");
script_end_attributes();

script_cve_id("CVE-2006-3403");
script_summary(english: "Check for the samba-1961 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"samba-3.0.22-13.23", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.22-13.23", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.22-13.23", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-3.0.22-13.23", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.22-13.23", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.22-13.23", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
