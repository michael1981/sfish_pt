# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-17.xml
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
 script_id(18538);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200506-17");
 script_cve_id("CVE-2005-1266", "CVE-2005-2024");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-17
(SpamAssassin 3, Vipul\'s Razor: Denial of Service vulnerability)


    SpamAssassin and Vipul\'s Razor contain a Denial of Service
    vulnerability when handling special misformatted long message headers.
  
Impact

    By sending a specially crafted message an attacker could cause a Denial
    of Service attack against the SpamAssassin/Vipul\'s Razor server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All SpamAssassin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/spamassassin-3.0.4"
    All Vipul\'s Razor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/razor-2.74"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1266');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2024');
script_set_attribute(attribute: 'see_also', value: 'http://mail-archives.apache.org/mod_mbox/spamassassin-announce/200506.mbox/%3c17072.35054.586017.822288@proton.pathname.com%3e');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/mailarchive/forum.php?thread_id=7520323&forum_id=4259');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-17] SpamAssassin 3, Vipul\'s Razor: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SpamAssassin 3, Vipul\'s Razor: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-filter/spamassassin", unaffected: make_list("ge 3.0.4", "lt 3.0.1"), vulnerable: make_list("lt 3.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-filter/razor", unaffected: make_list("ge 2.74"), vulnerable: make_list("lt 2.74")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
