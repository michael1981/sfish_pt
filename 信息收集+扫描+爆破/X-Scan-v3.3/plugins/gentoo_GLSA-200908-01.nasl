# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-01.xml
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
 script_id(40462);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200908-01");
 script_cve_id("CVE-2009-0368", "CVE-2009-1603");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-01
(OpenSC: Multiple vulnerabilities)


    Multiple vulnerabilities were found in OpenSC:
    b.badrignans discovered that OpenSC incorrectly initialises private
    data objects (CVE-2009-0368).
    Miquel Comas Marti discovered
    that src/tools/pkcs11-tool.c in pkcs11-tool in OpenSC 0.11.7, when used
    with unspecified third-party PKCS#11 modules, generates RSA keys with
    incorrect public exponents (CVE-2009-1603).
  
Impact

    The first vulnerabilty allows physically proximate attackers to bypass
    intended PIN requirements and read private data objects. The second
    vulnerability allows attackers to read the cleartext form of messages
    that were intended to be encrypted.
    NOTE: Smart cards which were initialised using an affected version of
    OpenSC need to be modified or re-initialised. See the vendor\'s advisory
    for details.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/opensc-0.11.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0368');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1603');
script_set_attribute(attribute: 'see_also', value: 'http://www.opensc-project.org/pipermail/opensc-announce/2009-February/000023.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-01] OpenSC: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSC: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/opensc", unaffected: make_list("ge 0.11.8"), vulnerable: make_list("lt 0.11.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
