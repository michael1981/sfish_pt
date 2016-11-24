# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-04.xml
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
 script_id(31034);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-04");
 script_cve_id("CVE-2007-6685", "CVE-2007-6686", "CVE-2007-6687", "CVE-2007-6688", "CVE-2007-6689", "CVE-2007-6690", "CVE-2007-6691", "CVE-2007-6692", "CVE-2007-6693");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-04
(Gallery: Multiple vulnerabilities)


    The Gallery developement team reported and fixed critical
    vulnerabilities during an internal audit (CVE-2007-6685, CVE-2007-6686,
    CVE-2007-6687, CVE-2007-6688, CVE-2007-6689, CVE-2007-6690,
    CVE-2007-6691, CVE-2007-6692, CVE-2007-6693).
  
Impact

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary code, conduct Cross-Site Scripting and Cross-Site Request
    Forgery attacks, or disclose sensitive informations.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gallery users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/gallery-2.2.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6685');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6686');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6687');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6688');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6689');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6690');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6691');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6692');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6693');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-04] Gallery: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 2.2.4", "lt 2.0"), vulnerable: make_list("lt 2.2.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
