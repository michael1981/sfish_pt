# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-06.xml
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
 script_id(14562);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-06");
 script_cve_id("CVE-2004-0796");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-06
(SpamAssassin: Denial of Service vulnerability)


    SpamAssassin contains an unspecified Denial of Service vulnerability.
  
Impact

    By sending a specially crafted message an attacker could cause a Denial
    of Service attack against the SpamAssassin service.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of SpamAssassin.
  
');
script_set_attribute(attribute:'solution', value: '
    All SpamAssassin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=mail-filter/spamassassin-2.64"
    # emerge ">=mail-filter/spamassassin-2.64"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://marc.theaimsgroup.com/?l=spamassassin-announce&m=109168121628767&w=2');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0796');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-06] SpamAssassin: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SpamAssassin: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-filter/spamassassin", unaffected: make_list("ge 2.64"), vulnerable: make_list("le 2.63-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
