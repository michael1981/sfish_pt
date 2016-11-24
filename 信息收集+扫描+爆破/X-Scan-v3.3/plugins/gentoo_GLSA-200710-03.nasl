# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-03.xml
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
 script_id(26943);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-03");
 script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-03
(libvorbis: Multiple vulnerabilities)


    David Thiel of iSEC Partners discovered a heap-based buffer overflow in
    the _01inverse() function in res0.c and a boundary checking error in
    the vorbis_info_clear() function in info.c (CVE-2007-3106 and
    CVE-2007-4029). libvorbis is also prone to several Denial of Service
    vulnerabilities in form of infinite loops and invalid memory access
    with unknown impact (CVE-2007-4065 and CVE-2007-4066).
  
Impact

    A remote attacker could exploit these vulnerabilities by enticing a
    user to open a specially crafted Ogg Vorbis file or network stream with
    an application using libvorbis. This might lead to the execution of
    arbitrary code with privileges of the user playing the file or a Denial
    of Service by a crash or CPU consumption.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libvorbis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libvorbis-1.2.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3106');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4029');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4065');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4066');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-03] libvorbis: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libvorbis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libvorbis", unaffected: make_list("ge 1.2.0"), vulnerable: make_list("lt 1.2.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
