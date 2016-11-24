# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-23.xml
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
 script_id(14774);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-23");
 script_cve_id("CVE-2004-1470");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-23
(SnipSnap: HTTP response splitting)


    SnipSnap contains various HTTP response splitting vulnerabilities that
    could potentially compromise the sites data. Some of these attacks
    include web cache poisoning, cross-user defacement, hijacking pages
    with sensitive user information, and cross-site scripting. This
    vulnerability is due to the lack of illegal input checking in the
    software.
  
Impact

    A malicious user could inject and execute arbitrary script code,
    potentially compromising the victim\'s data or browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SnipSnap users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-java/snipsnap-bin-1.0_beta1"
    # emerge ">=dev-java/snipsnap-bin-1.0beta1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://snipsnap.org/space/start/2004-09-14/1#SnipSnap_1.0b1_(uttoxeter)_released');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1470');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-23] SnipSnap: HTTP response splitting');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SnipSnap: HTTP response splitting');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/snipsnap-bin", unaffected: make_list("ge 1.0_beta1"), vulnerable: make_list("lt 1.0_beta1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
