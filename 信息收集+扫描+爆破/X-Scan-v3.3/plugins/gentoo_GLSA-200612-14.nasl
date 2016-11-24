# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-14.xml
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
 script_id(23866);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200612-14");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-14
(Trac: Cross-site request forgery)


    Trac allows users to perform certain tasks via HTTP requests without
    performing correct validation on those requests.
  
Impact

    An attacker could entice an authenticated user to browse to a specially
    crafted URL, allowing the attacker to execute actions in the Trac
    instance as if they were the user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5848
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5878

');
script_set_attribute(attribute:'solution', value: '
    All Trac users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/trac-0.10.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-14.xml');
script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-14] Trac: Cross-site request forgery');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_cve_id("CVE-2006-5878");
 script_summary(english: 'Trac: Cross-site request forgery');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/trac", unaffected: make_list("ge 0.10.1"), vulnerable: make_list("lt 0.10.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
