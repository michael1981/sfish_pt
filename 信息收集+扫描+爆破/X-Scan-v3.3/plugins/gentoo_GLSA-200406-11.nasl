# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-11.xml
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
 script_id(14522);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-11");
 script_cve_id("CVE-2004-0584");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-11
(Horde-IMP: Input validation vulnerability)


    Horde-IMP fails to properly sanitize email messages that contain
    malicious HTML or script code.
  
Impact

    By enticing a user to read a specially crafted e-mail, an attacker can
    execute arbitrary scripts running in the context of the victim\'s
    browser. This could lead to a compromise of the user\'s webmail account,
    cookie theft, etc.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Horde-IMP users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=www-apps/horde-imp-3.2.4"
    # emerge ">=www-apps/horde-imp-3.2.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/10501');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0584');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-11] Horde-IMP: Input validation vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde-IMP: Input validation vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-imp", unaffected: make_list("ge 3.2.4"), vulnerable: make_list("le 3.2.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
