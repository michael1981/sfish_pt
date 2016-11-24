# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-08.xml
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
 script_id(24206);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-08");
 script_cve_id("CVE-2007-0126", "CVE-2007-0127");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-08
(Opera: Two remote code execution vulnerabilities)


    Christoph Deal discovered that JPEG files with a specially crafted DHT
    marker can be exploited to cause a heap overflow. Furthermore, an
    anonymous person discovered that Opera does not correctly handle
    objects passed to the "createSVGTransformFromMatrix()" function.
  
Impact

    An attacker could potentially exploit the vulnerabilities to execute
    arbitrary code with the privileges of the user running Opera by
    enticing a victim to open a specially crafted JPEG file or a website
    containing malicious JavaScript code.
  
Workaround

    The vendor recommends disabling JavaScript to avoid the
    "createSVGTransformFromMatrix" vulnerability. There is no known
    workaround for the other vulnerability.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/support/search/supsearch.dml?index=851');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/support/search/supsearch.dml?index=852');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0126');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0127');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-08] Opera: Two remote code execution vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Two remote code execution vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.10"), vulnerable: make_list("lt 9.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
