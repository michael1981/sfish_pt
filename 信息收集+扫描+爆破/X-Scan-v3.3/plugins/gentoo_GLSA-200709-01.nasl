# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-01.xml
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
 script_id(26041);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200709-01");
 script_cve_id("CVE-2007-3999", "CVE-2007-4000");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-01
(MIT Kerberos 5: Multiple vulnerabilities)


    A stack buffer overflow (CVE-2007-3999) has been reported in
    svcauth_gss_validate() of the RPC library of kadmind. Another
    vulnerability (CVE-2007-4000) has been found in
    kadm5_modify_policy_internal(), which does not check the return values
    of krb5_db_get_policy() correctly.
  
Impact

    The RPC related vulnerability can be exploited by a remote
    unauthenticated attacker to execute arbitrary code with root privileges
    on the host running kadmind. The second vulnerability requires the
    remote attacker to be authenticated and to have "modify policy"
    privileges. It could then also allow for the remote execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.5.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3999');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4000');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-01] MIT Kerberos 5: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.5.3-r1"), vulnerable: make_list("lt 1.5.3-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
