# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-14.xml
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
 script_id(31961);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200804-14");
 script_cve_id("CVE-2008-1761", "CVE-2008-1762", "CVE-2008-1764");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-14
(Opera: Multiple vulnerabilities)


    Michal Zalewski reported two vulnerabilities, memory corruption when
    adding news feed sources from a website (CVE-2008-1761) as well as when
    processing HTML CANVAS elements to use scaled images (CVE-2008-1762).
    Additionally, an unspecified weakness related to keyboard handling of
    password inputs has been reported (CVE-2008-1764).
  
Impact

    A remote attacker could entice a user to visit a specially crafted web
    site or news feed and possibly execute arbitrary code with the
    privileges of the user running Opera.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.27"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1761');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1762');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1764');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-14] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.27"), vulnerable: make_list("lt 9.27")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
