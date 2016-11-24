# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml
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
 script_id(25793);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200707-11");
 script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-11
(MIT Kerberos 5: Arbitrary remote code execution)


    kadmind is affected by multiple vulnerabilities in the RPC library
    shipped with MIT Kerberos 5. It fails to properly handle zero-length
    RPC credentials (CVE-2007-2442) and the RPC library can write past the
    end of the stack buffer (CVE-2007-2443). Furthermore kadmind fails to
    do proper bounds checking (CVE-2007-2798).
  
Impact

    A remote unauthenticated attacker could exploit these vulnerabilities
    to execute arbitrary code with root privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.5.2-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2442');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2443');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2798');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-11] MIT Kerberos 5: Arbitrary remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Arbitrary remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.5.2-r3"), vulnerable: make_list("lt 1.5.2-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
