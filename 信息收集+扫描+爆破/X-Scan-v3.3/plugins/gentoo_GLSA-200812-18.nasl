# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-18.xml
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
 script_id(35189);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-18");
 script_cve_id("CVE-2008-3520", "CVE-2008-3522");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-18
(JasPer: User-assisted execution of arbitrary code)


    Marc Espie and Christian Weisgerber have discovered multiple
    vulnerabilities in JasPer:
    Multiple integer overflows might allow for insufficient memory
    allocation, leading to heap-based buffer overflows (CVE-2008-3520).
    The jas_stream_printf() function in libjasper/base/jas_stream.c uses
    vsprintf() to write user-provided data to a static to a buffer, leading
    to an overflow (CVE-2008-3522).
  
Impact

    Remote attackers could entice a user or automated system to process
    specially crafted jpeg2k files with an application using JasPer,
    possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All JasPer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/jasper-1.900.1-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3520');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3522');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-18] JasPer: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JasPer: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/jasper", unaffected: make_list("ge 1.900.1-r3"), vulnerable: make_list("lt 1.900.1-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
