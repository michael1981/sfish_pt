# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-06.xml
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
 script_id(15608);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200411-06");
 script_cve_id("CVE-2004-1098");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-06
(MIME-tools: Virus detection evasion)


    MIME-tools doesn\'t correctly parse attachment boundaries with an empty
    name (boundary="").
  
Impact

    An attacker could send a carefully crafted email and evade detection on
    some email virus-scanning programs using MIME-tools for attachment
    decoding.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIME-tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/MIME-tools-5.415"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://lists.roaringpenguin.com/pipermail/mimedefang/2004-October/024959.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1098');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-06] MIME-tools: Virus detection evasion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIME-tools: Virus detection evasion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-perl/MIME-tools", unaffected: make_list("ge 5.415"), vulnerable: make_list("lt 5.415")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
