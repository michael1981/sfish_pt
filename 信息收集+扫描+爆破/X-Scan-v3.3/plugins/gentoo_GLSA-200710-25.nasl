# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-25.xml
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
 script_id(27557);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-25");
 script_cve_id("CVE-2007-5714");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-25
(MLDonkey: Privilege escalation)


    The Gentoo MLDonkey ebuild adds a user to the system named "p2p" so
    that the MLDonkey service can run under a user with low privileges.
    With older Portage versions this user is created with a valid login
    shell and no password.
  
Impact

    A remote attacker could log into a vulnerable system as the p2p user.
    This would require an installed login service that permitted empty
    passwords, such as SSH configured with the "PermitEmptyPasswords yes"
    option, a local login console, or a telnet server.
  
Workaround

    See Resolution.
  
');
script_set_attribute(attribute:'solution', value: '
    Change the p2p user\'s shell to disallow login. For example, as root run
    the following command:
    # usermod -s /bin/false p2p
    NOTE: updating to the current MLDonkey ebuild will not remove this
    vulnerability, it must be fixed manually. The updated ebuild is to
    prevent this problem from occurring in the future.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5714');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-25] MLDonkey: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MLDonkey: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/mldonkey", unaffected: make_list("ge 2.9.0-r3"), vulnerable: make_list("lt 2.9.0-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
