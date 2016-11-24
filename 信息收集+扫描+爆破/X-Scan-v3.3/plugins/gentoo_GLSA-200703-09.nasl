# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-09.xml
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
 script_id(24801);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-09");
 script_cve_id("CVE-2007-0472", "CVE-2007-0473", "CVE-2007-0474", "CVE-2007-0475");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-09
(Smb4K: Multiple vulnerabilities)


    Kees Cook of the Ubuntu Security Team has identified multiple
    vulnerabilities in Smb4K.
    The writeFile() function of
    smb4k/core/smb4kfileio.cpp makes insecure usage of temporary
    files.
    The writeFile() function also stores the contents of
    the sudoers file with incorrect permissions, allowing for the file\'s
    contents to be world-readable.
    The createLockFile() and
    removeLockFile() functions improperly handle lock files, possibly
    allowing for a race condition in file handling.
    The smb4k_kill
    utility distributed with Smb4K allows any user in the sudoers group to
    kill any process on the system.
    Lastly, there is the potential
    for multiple stack overflows when any Smb4K utility is used with the
    sudo command.
  
Impact

    A local attacker could gain unauthorized access to arbitrary files via
    numerous attack vectors. In some cases to obtain this unauthorized
    access, an attacker would have to be a member of the sudoers list.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Smb4K users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/smb4k-0.6.10a"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0472');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0473');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0474');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0475');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-09] Smb4K: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Smb4K: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/smb4k", unaffected: make_list("ge 0.6.10a"), vulnerable: make_list("lt 0.6.10a")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
