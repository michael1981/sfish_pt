# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-10.xml
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
 script_id(34250);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200809-10");
 script_cve_id("CVE-2008-2276", "CVE-2008-3331", "CVE-2008-3332", "CVE-2008-3333");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-10
(Mantis: Multiple vulnerabilities)


    Antonio Parata and Francesco Ongaro reported a Cross-Site Request
    Forgery vulnerability in manage_user_create.php (CVE-2008-2276), a
    Cross-Site Scripting vulnerability in return_dynamic_filters.php
    (CVE-2008-3331), and an insufficient input validation in
    adm_config_set.php (CVE-2008-3332). A directory traversal vulnerability
    in core/lang_api.php (CVE-2008-3333) has also been reported.
  
Impact

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary HTML and script code, create arbitrary users with
    administrative privileges, execute arbitrary PHP commands, and include
    arbitrary files.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mantis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mantisbt-1.1.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2276');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3331');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3332');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3333');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-10] Mantis: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mantis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/mantisbt", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
