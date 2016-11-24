# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml
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
 script_id(25382);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200705-23");
 script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-23
(Sun JDK/JRE: Multiple vulnerabilities)


    An unspecified vulnerability involving an "incorrect use of system
    classes" was reported by the Fujitsu security team. Additionally, Chris
    Evans from the Google Security Team reported an integer overflow
    resulting in a buffer overflow in the ICC parser used with JPG or BMP
    files, and an incorrect open() call to /dev/tty when processing certain
    BMP files.
  
Impact

    A remote attacker could entice a user to run a specially crafted Java
    class or applet that will trigger one of the vulnerabilities. This
    could lead to the execution of arbitrary code outside of the Java
    sandbox and of the Java security restrictions, or crash the Java
    application or the browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun Java Development Kit users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-java/sun-jdk"
    All Sun Java Runtime Environment users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-java/sun-jre-bin"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2435');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2788');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2789');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-23] Sun JDK/JRE: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.01", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.5.0.12", "rge 1.5.0.11", "rge 1.4.2.18", "rge 1.4.2.17", "rge 1.4.2.15", "rge 1.4.2.14", "rge 1.4.2.19", "rge 1.5.0.17", "rge 1.5.0.18"), vulnerable: make_list("lt 1.6.0.01")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.5.0.11", "rge 1.4.2.14", "rge 1.4.2.15", "rge 1.4.2.19"), vulnerable: make_list("lt 1.5.0.11")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
