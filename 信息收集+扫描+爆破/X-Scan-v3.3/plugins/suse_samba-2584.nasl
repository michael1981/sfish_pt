
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27428);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  samba: Fix logic error in the deferred open code and some other issues. (samba-2584)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch samba-2584");
 script_set_attribute(attribute: "description", value: "A logic error in the deferred open code can lead to an
infinite loop in Samba's smbd daemon.

In addition the following changes are included with these
packages:

- Disable broken DCERPC funnel patch; [#242833].
- Avoid winbind event handler for internal domains.
- Fix smbcontrol winbind offline; [#223418].
- Fail on offline pwd change attempts; [#223501].
- Register check_dom_handler when coming from offline mode.
- Fix pam_winbind passwd changes in online mode.
- Call set_domain_online in init_domain_list().
- Winbind cleanup after failure and fix crash bug.
- Don't register check domain handler for all trusts.
- Add separate logfile for dc-connect wb child.
- Only write custom krb5 conf for own domain.
- Move check domain handler to fork_domain_child.
- Fix pam_winbind text string typo; [#238496].
- Support sites without DCs (automatic site coverage);
  [#219793].
- Fix invalid krb5 cred cache deletion; [#227782].
- Fix invalid warning in the PAM session close;
- Fix DC queries for all DCs; [#230963].
- Fix sitename usage depending on realm; [#195354].
- Add DCERPC funnel patch; fate [#300768].
- Fix pam password change with w2k DCs; [#237281].
- Check from the init script for SAMBA_<daemonname>_ENV
  variable expected to be set in /etc/sysconfig/samba to
  export a particular environment variable before starting
  a daemon.  See section 'Setup a particular environment
  for a Samba daemon' from the README file how this feature
  is to use.
- Remove %config tag from /usr/share/omc/svcinfo.d/*.xml
  files.
- Fix pam_winbind grace offline logins; [#223501].
- Fix password expiry message; [#231583].
- Move XML service description documents; fate [#301712].
- Disable smbmnt, smbmount, and smbumount for systems newer
  than 10.1.
- Add XML service description documents; fate [#301712].
- Move tdb utils to the client package.
- Fix crash caused by deleting a message dispatch handler
  from inside the handler itself; [#221709].
- Fix delays in winbindd access when on a non-home network;
  [#222595].
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch samba-2584");
script_end_attributes();

script_summary(english: "Check for the samba-2584 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"samba-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-32bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-64bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-32bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-64bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-32bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-64bit-3.0.23d-19.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
