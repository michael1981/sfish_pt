# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14486);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-21");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-21
(Multiple Vulnerabilities in Samba)


    Two vulnerabilities have been discovered in Samba. The first vulnerability
    allows a local user who has access to the smbmount command to gain root. An
    attacker could place a setuid-root binary on a Samba share/server he or she
    controls, and then use the smbmount command to mount the share on the
    target UNIX box. The remote Samba server must support UNIX extensions for
    this to work. This has been fixed in version 3.0.2a.
    The second vulnerability is in the smbprint script. By creating a symlink
    from /tmp/smbprint.log, an attacker could cause the smbprint script to
    write to an arbitrary file on the system. This has been fixed in version
    3.0.2a-r2.
  
Impact

    Local users with access to the smbmount command may gain root access. Also,
    arbitrary files may be overwritten using the smbprint script.
  
Workaround

    To workaround the setuid bug, remove the setuid bits from the
    /usr/bin/smbmnt, /usr/bin/smbumount and /usr/bin/mount.cifs binaries.
    However, please note that this workaround will prevent ordinary users from
    mounting remote SMB and CIFS shares.
    To work around the smbprint vulnerability, set "debug=no" in the smbprint
    configuration.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should update to the latest version of the Samba package.
    The following commands will perform the upgrade:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.2a-r2"
    # emerge ">=net-fs/samba-3.0.2a-r2"
    Those who are using Samba\'s password database also need to run the
    following command:
    # pdbedit --force-initialized-passwords
    Those using LDAP for Samba passwords also need to check the sambaPwdLastSet
    attribute on each account, and ensure it is not 0.
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/353222/2004-04-09/2004-04-15/1');
script_set_attribute(attribute: 'see_also', value: 'http://seclists.org/lists/bugtraq/2004/Mar/0189.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-21] Multiple Vulnerabilities in Samba');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Vulnerabilities in Samba');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.2a-r2"), vulnerable: make_list("le 3.0.2a")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
