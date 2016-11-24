# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-20.xml
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
 script_id(32013);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200804-20");
 script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-5232", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689", "CVE-2008-0628", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-20
(Sun JDK/JRE: Multiple vulnerabilities)

Impact

    A remote attacker could entice a user to run a specially crafted applet
    on a website or start an application in Java Web Start to execute
    arbitrary code outside of the Java sandbox and of the Java security
    restrictions with the privileges of the user running Java. The attacker
    could also obtain sensitive information, create, modify, rename and
    read local files, execute local applications, establish connections in
    the local network, bypass the same origin policy, and cause a Denial of
    Service via multiple vectors.
  
Workaround

    There is no known workaround at this time.
  

');
script_set_attribute(attribute:'solution', value: '
    All Sun JRE 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.6.0.05"
    All Sun JRE 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.5.0.15"
    All Sun JRE 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.17"
    All Sun JDK 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.6.0.05"
    All Sun JDK 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.5.0.15"
    All Sun JDK 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.17"
    All emul-linux-x86-java 1.6 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-java-1.6.0.05"
    All emul-linux-x86-java 1.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-java-1.5.0.15"
    All emul-linux-x86-java 1.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-java-1.4.2.17"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2435');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2788');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2789');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3655');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5232');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5237');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5238');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5239');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5240');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5273');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5274');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5689');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0628');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0657');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1185');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1186');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1187');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1188');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1189');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1190');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1191');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1192');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1193');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1194');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1195');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1196');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-23.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-08.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-20] Sun JDK/JRE: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun JDK/JRE: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-emulation/emul-linux-x86-java", unaffected: make_list("ge 1.6.0.05", "rge 1.5.0.21", "rge 1.5.0.20", "rge 1.5.0.19", "rge 1.5.0.18", "rge 1.5.0.17", "rge 1.5.0.16", "rge 1.5.0.15", "rge 1.4.2.17"), vulnerable: make_list("lt 1.6.0.05")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
