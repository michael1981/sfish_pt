# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-06.xml
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
 script_id(14653);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-06");
 script_cve_id("CVE-2004-1467");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-06
(eGroupWare: Multiple XSS vulnerabilities)


    Joxean Koret recently discovered multiple cross site scripting
    vulnerabilities in various modules for the eGroupWare suite. This
    includes the calendar, address book, messenger and ticket modules.
  
Impact

    These vulnerabilities give an attacker the ability to inject and
    execute malicious script code, potentially compromising the victim\'s
    browser.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of eGroupWare.
  
');
script_set_attribute(attribute:'solution', value: '
    All eGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/egroupware-1.0.00.004"
    # emerge ">=www-apps/egroupware-1.0.00.004"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'https://sourceforge.net/forum/forum.php?forum_id=401807');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/372603/2004-08-21/2004-08-27/0');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1467');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-06] eGroupWare: Multiple XSS vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'eGroupWare: Multiple XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.00.004"), vulnerable: make_list("le 1.0.00.003")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
