
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27426);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  samba: Fix memory exhaustion DoS and many other issues. (samba-1830)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch samba-1830");
 script_set_attribute(attribute: "description", value: "- Prevent potential crash in winbindd's credential cache
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
- Add CHANGEPW kpasswd fallback to TCP; [#184945].
- Honour 'sn' attribute for eDir; [#176799].
- Adapt smbclient fix to smbtree to enable long share
  names; [#175999].
- Make smbclient -L use RPC to list shares, fall back to
  RAP; [#171311].
- Re-add in-forest domain trusts; [bso #3823].
- Remove SO_SNDBUF and SO_RCVBUF from socket options
  example; [#165723].
- Add wbinfo --own-domain; [#167344].
- Fix usability of pam_winbind on a Samba PDC; [bso #3800].
- Remove intrusive affinity patches for winbindd.
- Merge Volker's winbindd crash fix for half-opened
  connections in winbindd_cm.c (sessionsetup succeeded but
  tconX failed).
- Optimize lookup of user's group memberships via
  ExtendedDn LDAP control; [#168100].
- Restart winbind if the hostname is modified by the DHCP
  client; [#169260].
- Prevent passwords beeing swapped to disc; [#174834].
- Remove length limit from winbind cache cleanup function;
  [#175737].
- Fix NDS_ldapsam memory leak.
- Only add password to linked list when necessary.
- Don't try cached credentials when changing passwords.
- Cleanup winbind linked list of credential caches.
- Use the index objectCategory attribute in AD LDAP
  requests.
- Adjust AD time difference when validating tickets.
- Add password change warning for passwords beeing too
  young.
- Remove experimental Heimdal KCM support.
- Added 'usershare allow guests' global parameter;
  [#144787].
- Return domain name in samrquerydominfo 5; [#172756].
- Fix unauthorized access when logging in with pam_winbind;
  [#156385].
- Don't ever set O_SYNC on open unless 'strict sync = yes';
  [#165431].
- Correct fix to exit from 'net' with an inproper
  configuration; [#163227], [#182749].
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch samba-1830");
script_end_attributes();

script_cve_id("CVE-2006-3403");
script_summary(english: "Check for the samba-1830 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"samba-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-32bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-64bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-32bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-client-64bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-32bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"samba-winbind-64bit-3.0.22-13.18", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
