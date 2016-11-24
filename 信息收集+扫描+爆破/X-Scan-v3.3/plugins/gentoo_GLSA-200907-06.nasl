# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-06.xml
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
 script_id(39777);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200907-06");
 script_cve_id("CVE-2009-0198", "CVE-2009-0509", "CVE-2009-0510", "CVE-2009-0511", "CVE-2009-0512", "CVE-2009-0888", "CVE-2009-0889", "CVE-2009-1492", "CVE-2009-1493", "CVE-2009-1855", "CVE-2009-1856", "CVE-2009-1857", "CVE-2009-1858", "CVE-2009-1859", "CVE-2009-1861", "CVE-2009-2028");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-06
(Adobe Reader: User-assisted execution of arbitrary code)


    Multiple vulnerabilities have been reported in Adobe Reader:
    Alin Rad Pop of Secunia Research reported a heap-based buffer
    overflow in the JBIG2 filter (CVE-2009-0198).
    Mark Dowd of the IBM Internet Security Systems X-Force and
    Nicolas Joly of VUPEN Security reported multiple heap-based buffer
    overflows in the JBIG2 filter (CVE-2009-0509, CVE-2009-0510,
    CVE-2009-0511, CVE-2009-0512, CVE-2009-0888, CVE-2009-0889)
    Arr1val reported that multiple methods in the JavaScript API
    might lead to memory corruption when called with crafted arguments
    (CVE-2009-1492, CVE-2009-1493).
    An anonymous researcher reported a stack-based buffer overflow related
    to U3D model files with a crafted extension block (CVE-2009-1855).
    Jun Mao and Ryan Smith of iDefense Labs reported an integer overflow
    related to the FlateDecode filter, which triggers a heap-based buffer
    overflow (CVE-2009-1856).
    Haifei Li of Fortinet\'s FortiGuard Global Security Research Team
    reported a memory corruption vulnerability related to TrueType fonts
    (CVE-2009-1857).
    The Apple Product Security Team reported a memory corruption
    vulnerability in the JBIG2 filter (CVE-2009-1858).
    Matthew Watchinski of Sourcefire VRT reported an unspecified memory
    corruption (CVE-2009-1859).
    Will Dormann of CERT reported multiple heap-based buffer overflows when
    processing JPX (aka JPEG2000) stream that trigger heap memory
    corruption (CVE-2009-1861).
    Multiple unspecified vulnerabilities have been discovered
    (CVE-2009-2028).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-8.1.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0198');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0509');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0510');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0511');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0512');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0888');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0889');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1492');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1493');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1855');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1856');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1857');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1858');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1859');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1861');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2028');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-06] Adobe Reader: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Reader: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 8.1.6"), vulnerable: make_list("lt 8.1.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
