# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-15.xml
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
 script_id(27050);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-15");
 script_cve_id("CVE-2007-4569");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-15
(KDM: Local privilege escalation)


    Kees Huijgen discovered an error when checking the credentials which
    can lead to a login without specifying a password. This only occurs
    when auto login is configured for at least one user and a password is
    required to shut down the machine.
  
Impact

    A local attacker could gain root privileges and execute arbitrary
    commands by logging in as root without specifying root\'s password.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All KDM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdm-3.5.7-r2"
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdebase-3.5.7-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4569');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-15] KDM: Local privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDM: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdm", unaffected: make_list("ge 3.5.7-r2"), vulnerable: make_list("lt 3.5.7-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("ge 3.5.7-r4"), vulnerable: make_list("lt 3.5.7-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
