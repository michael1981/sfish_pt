# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-02.xml
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
 script_id(31329);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-02");
 script_cve_id("CVE-2008-0387", "CVE-2008-0467");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-02
(Firebird: Multiple vulnerabilities)


    Firebird does not properly handle certain types of XDR requests,
    resulting in an integer overflow (CVE-2008-0387). Furthermore, it is
    vulnerable to a buffer overflow when processing usernames
    (CVE-2008-0467).
  
Impact

    A remote attacker could send specially crafted XDR requests or an
    overly long username to the vulnerable server, possibly resulting in
    the remote execution of arbitrary code with the privileges of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Firebird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/firebird-2.0.3.12981.0-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0387');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0467');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-02] Firebird: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Firebird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/firebird", unaffected: make_list("ge 2.0.3.12981.0-r5"), vulnerable: make_list("lt 2.0.3.12981.0-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
