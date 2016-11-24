# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-14.xml
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
 script_id(15511);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-14");
 script_cve_id("CVE-2004-2630");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-14
(phpMyAdmin: Vulnerability in MIME-based transformation system)


    A defect was found in phpMyAdmin\'s MIME-based transformation system,
    when used with "external" transformations.
  
Impact

    A remote attacker could exploit this vulnerability to execute arbitrary
    commands on the server with the rights of the HTTP server user.
  
Workaround

    Enabling PHP safe mode ("safe_mode = On" in php.ini) may serve as a
    temporary workaround.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/phpmyadmin-2.6.0_p2"
    # emerge ">=dev-db/phpmyadmin-2.6.0_p2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/forum/forum.php?forum_id=414281');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/12813/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2630');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-14] phpMyAdmin: Vulnerability in MIME-based transformation system');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Vulnerability in MIME-based transformation system');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.0_p2"), vulnerable: make_list("lt 2.6.0_p2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
