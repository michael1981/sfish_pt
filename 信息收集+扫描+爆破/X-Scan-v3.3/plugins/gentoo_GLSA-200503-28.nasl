# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-28.xml
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
 script_id(17615);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200503-28");
 script_cve_id("CVE-2005-0836");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-28
(Sun Java: Web Start argument injection vulnerability)


    Jouko Pynnonen discovered that Java Web Start contains a vulnerability
    in the way it handles property tags in JNLP files.
  
Impact

    By enticing a user to open a malicious JNLP file, a remote attacker
    could pass command line arguments to the Java Virtual machine, which
    can be used to bypass the Java "sandbox" and to execute arbitrary code
    with the permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sun JDK users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jdk-1.4.2.07"
    All Sun JRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-java/sun-jre-bin-1.4.2.07"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://jouko.iki.fi/adv/ws.html');
script_set_attribute(attribute: 'see_also', value: 'http://sunsolve.sun.com/search/document.do?assetkey=1-26-57740-1');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0836');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-28] Sun Java: Web Start argument injection vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sun Java: Web Start argument injection vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-java/sun-jre-bin", unaffected: make_list("ge 1.4.2.07", "lt 1.4.2"), vulnerable: make_list("lt 1.4.2.07")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-java/sun-jdk", unaffected: make_list("ge 1.4.2.07", "lt 1.4.2"), vulnerable: make_list("lt 1.4.2.07")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
