# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-17.xml
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
 script_id(26040);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200708-17");
 script_cve_id("CVE-2007-3142", "CVE-2007-3819", "CVE-2007-3929", "CVE-2007-4367");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-17
(Opera: Multiple vulnerabilities)


    An error known as "a virtual function call on an invalid pointer" has
    been discovered in the JavaScript engine (CVE-2007-4367). Furthermore,
    iDefense Labs reported that an already-freed pointer may be still used
    under unspecified circumstances in the BitTorrent support
    (CVE-2007-3929). At last, minor other errors have been discovered,
    relative to memory read protection (Opera Advisory 861) and URI
    displays (CVE-2007-3142, CVE-2007-3819).
  
Impact

    A remote attacker could trigger the BitTorrent vulnerability by
    enticing a user into starting a malicious BitTorrent download, and
    execute arbitrary code through unspecified vectors. Additionally, a
    specially crafted JavaScript may trigger the "virtual function"
    vulnerability. The JavaScript engine can also access previously freed
    but uncleaned memory. Finally, a user can be fooled with a too long
    HTTP server name that does not fit the dialog box, or a URI containing
    whitespaces.
  
Workaround

    There is no known workaround at this time for all these
    vulnerabilities.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.23"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3142');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3819');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3929');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4367');
script_set_attribute(attribute: 'see_also', value: 'http://www.opera.com/support/search/view/861/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-17] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.23"), vulnerable: make_list("lt 9.23")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
