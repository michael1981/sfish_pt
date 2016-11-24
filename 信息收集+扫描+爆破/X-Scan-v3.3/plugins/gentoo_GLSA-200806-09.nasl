# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-09.xml
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
 script_id(33245);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200806-09");
 script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-09
(libvorbis: Multiple vulnerabilities)


    Will Drewry of the Google Security Team reported multiple
    vulnerabilities in libvorbis:
    A zero value for "codebook.dim" is not properly handled, leading to a
    crash, infinite loop or triggering an integer overflow
    (CVE-2008-1419).
    An integer overflow in "residue partition value" evaluation might lead
    to a heap-based buffer overflow (CVE-2008-1420).
    An integer overflow in a certain "quantvals" and "quantlist"
    calculation might lead to a heap-based buffer overflow
    (CVE-2008-1423).
  
Impact

    A remote attacker could exploit these vulnerabilities by enticing a
    user to open a specially crafted Ogg Vorbis file or network stream with
    an application using libvorbis. This might lead to the execution of
    arbitrary code with the privileges of the user playing the file or a
    Denial of Service by a crash or CPU consumption.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libvorbis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libvorbis-1.2.1_rc1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1419');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1420');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1423');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-09] libvorbis: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libvorbis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libvorbis", unaffected: make_list("ge 1.2.1_rc1"), vulnerable: make_list("lt 1.2.1_rc1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
