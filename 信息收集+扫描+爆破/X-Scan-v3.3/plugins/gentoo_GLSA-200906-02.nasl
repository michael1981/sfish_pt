# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200906-02.xml
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
 script_id(39565);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200906-02");
 script_cve_id("CVE-2009-1904");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200906-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200906-02
(Ruby: Denial of Service)


    Tadayoshi Funaba reported that BigDecimal in
    ext/bigdecimal/bigdecimal.c does not properly handle string arguments
    containing overly long numbers.
  
Impact

    A remote attacker could exploit this issue to remotely cause a Denial
    of Service attack.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ruby users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.6_p369"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1904');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200906-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200906-02] Ruby: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("ge 1.8.6_p369"), vulnerable: make_list("lt 1.8.6_p369")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
