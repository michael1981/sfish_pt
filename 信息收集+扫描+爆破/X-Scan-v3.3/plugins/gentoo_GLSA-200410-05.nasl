# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-05.xml
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
 script_id(15431);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-05");
 script_cve_id("CVE-2004-0884", "CVE-2005-0373");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-05
(Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities)


    Cyrus-SASL contains a remote buffer overflow in the digestmda5.c file.
    Additionally, under certain conditions it is possible for a local user
    to exploit a vulnerability in the way the SASL_PATH environment
    variable is honored (CAN-2004-0884).
  
Impact

    An attacker might be able to execute arbitrary code with the Effective
    ID of the application calling the Cyrus-SASL libraries.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cyrus-SASL users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-libs/cyrus-sasl-2.1.18-r2"
    # emerge ">=dev-libs/cyrus-sasl-2.1.18-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0884');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0373');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-05] Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/cyrus-sasl", unaffected: make_list("ge 2.1.18-r2"), vulnerable: make_list("le 2.1.18-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
