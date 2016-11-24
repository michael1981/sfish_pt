# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml
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
 script_id(25593);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200706-08");
 script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-08
(emul-linux-x86-java: Multiple vulnerabilities)


    Chris Evans of the Google Security Team has discovered an integer
    overflow in the ICC parser, and another vulnerability in the BMP
    parser. An unspecified vulnerability involving an "incorrect use of
    system classes" was reported by the Fujitsu security team.
  
Impact

    A remote attacker could entice a user to open a specially crafted
    image, possibly resulting in the execution of arbitrary code with the
    privileges of the user running Emul-linux-x86-java. They also could
    entice a user to open a specially crafted BMP image, resulting in a
    Denial of Service. Note that these vulnerabilities may also be
    triggered by a tool processing image files automatically.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Emul-linux-x86-java users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-java-1.5.0.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2435');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2788');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2789');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-08] emul-linux-x86-java: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'emul-linux-x86-java: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.5.0.11", "rge 1.4.2.16", "rge 1.4.2.17", "rge 1.4.2.19"), vulnerable: make_list("lt 1.5.0.11")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
