# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-19.xml
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
 script_id(32012);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-19");
 script_cve_id("CVE-2008-1734");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-19
(PHP Toolkit: Data disclosure and Denial of Service)


    Toni Arnold, David Sveningsson, Michal Bartoszkiewicz, and Joseph
    reported that php-select does not quote parameters passed to the "tr"
    command, which could convert the "-D PHP5" argument in the
    "APACHE2_OPTS" setting in the file /etc/conf.d/apache2 to lower case.
  
Impact

    An attacker could entice a system administrator to run "emerge
    php" or call "php-select -t apache2 php5" directly in a
    directory containing a lower case single-character named file, which
    would prevent Apache from loading mod_php and thereby disclose PHP
    source code and cause a Denial of Service.
  
Workaround

    Do not run "emerge" or "php-select" from a working directory which
    contains a lower case single-character named file.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP Toolkit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/php-toolkit-1.0.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1734');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-19] PHP Toolkit: Data disclosure and Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP Toolkit: Data disclosure and Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/php-toolkit", unaffected: make_list("ge 1.0.1"), vulnerable: make_list("lt 1.0.1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
