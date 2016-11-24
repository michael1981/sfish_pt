# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-07.xml
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
 script_id(40632);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200908-07");
 script_cve_id("CVE-2009-1391", "CVE-2009-1884");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-07
(Perl Compress::Raw modules: Denial of Service)


    Leo Bergolth reported an off-by-one error in the inflate() function in
    Zlib.xs of Compress::Raw::Zlib, possibly leading to a heap-based buffer
    overflow (CVE-2009-1391).
    Paul Marquess discovered a similar vulnerability in the bzinflate()
    function in Bzip2.xs of Compress::Raw::Bzip2 (CVE-2009-1884).
  
Impact

    A remote attacker might entice a user or automated system (for instance
    running SpamAssassin or AMaViS) to process specially crafted files,
    possibly resulting in a Denial of Service condition.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Compress::Raw::Zlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =perl-core/Compress-Raw-Zlib-2.020
    All Compress::Raw::Bzip2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =perl-core/Compress-Raw-Bzip2-2.020
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1391');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1884');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-07] Perl Compress::Raw modules: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl Compress::Raw modules: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "perl-core/Compress-Raw-Zlib", unaffected: make_list("ge 2.020"), vulnerable: make_list("lt 2.020")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "perl-core/Compress-Raw-Bzip2", unaffected: make_list("ge 2.020"), vulnerable: make_list("lt 2.020")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
