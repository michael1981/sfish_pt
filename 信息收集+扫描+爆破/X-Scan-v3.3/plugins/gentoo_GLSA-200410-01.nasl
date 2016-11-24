# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-01.xml
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
 script_id(15407);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-01");
 script_cve_id("CVE-2004-1773");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-01
(sharutils: Buffer overflows in shar.c and unshar.c)


    sharutils contains two buffer overflows. Ulf Harnhammar discovered a
    buffer overflow in shar.c, where the length of data returned by the wc
    command is not checked. Florian Schilhabel discovered another buffer
    overflow in unshar.c.
  
Impact

    An attacker could exploit these vulnerabilities to execute arbitrary
    code as the user running one of the sharutils programs.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All sharutils users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-arch/sharutils-4.2.1-r10"
    # emerge ">=app-arch/sharutils-4.2.1-r10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=265904');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1773');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-01] sharutils: Buffer overflows in shar.c and unshar.c');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sharutils: Buffer overflows in shar.c and unshar.c');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/sharutils", unaffected: make_list("ge 4.2.1-r10"), vulnerable: make_list("le 4.2.1-r9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
