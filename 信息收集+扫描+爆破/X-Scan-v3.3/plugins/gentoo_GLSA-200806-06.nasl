# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200806-06.xml
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
 script_id(33203);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200806-06");
 script_cve_id("CVE-2008-1108", "CVE-2008-1109");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200806-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200806-06
(Evolution: User-assisted execution of arbitrary code)


    Alin Rad Pop (Secunia Research) reported two vulnerabilities in
    Evolution:
    A boundary error exists when parsing overly long timezone strings
    contained within iCalendar attachments and when the ITip formatter is
    disabled (CVE-2008-1108).
    A boundary error exists when replying to an iCalendar request with an
    overly long "DESCRIPTION" property while in calendar view
    (CVE-2008-1109).
  
Impact

    A remote attacker could entice a user to open a specially crafted
    iCalendar attachment, resulting in the execution of arbitrary code with
    the privileges of the user running Evolution.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/evolution-2.12.3-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1108');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1109');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200806-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200806-06] Evolution: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Evolution: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/evolution", unaffected: make_list("ge 2.12.3-r2"), vulnerable: make_list("lt 2.12.3-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
