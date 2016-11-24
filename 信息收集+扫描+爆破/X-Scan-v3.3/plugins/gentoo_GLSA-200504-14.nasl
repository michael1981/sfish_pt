# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-14.xml
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
 script_id(18061);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-14");
 script_cve_id("CVE-2005-1122", "CVE-2005-1123");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-14
(monkeyd: Multiple vulnerabilities)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a
    double expansion error in monkeyd, resulting in a format string
    vulnerability. Ciaran McCreesh of Gentoo Linux discovered a Denial of
    Service vulnerability, a syntax error caused monkeyd to zero out
    unallocated memory should a zero byte file be requested.
  
Impact

    The format string vulnerability could allow an attacker to send a
    specially crafted request to the monkeyd server, resulting in the
    execution of arbitrary code with the permissions of the user running
    monkeyd. The DoS vulnerability could allow an attacker to disrupt the
    operation of the web server, should a zero byte file be accessible.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All monkeyd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/monkeyd-0.9.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1122');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1123');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-14] monkeyd: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'monkeyd: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/monkeyd", unaffected: make_list("ge 0.9.1"), vulnerable: make_list("lt 0.9.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
