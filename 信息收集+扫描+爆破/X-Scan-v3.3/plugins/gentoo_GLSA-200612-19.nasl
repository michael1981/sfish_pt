# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-19.xml
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
 script_id(23956);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-19");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-19
(pam_ldap: Authentication bypass vulnerability)


    Steve Rigler discovered that pam_ldap does not correctly handle
    "PasswordPolicyResponse" control responses from an LDAP directory. This
    causes the pam_authenticate() function to always succeed, even if the
    previous authentication failed.
  
Impact

    A locked user may exploit this vulnerability to bypass the LDAP
    authentication mechanism, possibly gaining unauthorized access to the
    system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All pam_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-auth/pam_ldap-183"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5170');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-19] pam_ldap: Authentication bypass vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pam_ldap: Authentication bypass vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-auth/pam_ldap", unaffected: make_list("ge 183"), vulnerable: make_list("lt 183")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
