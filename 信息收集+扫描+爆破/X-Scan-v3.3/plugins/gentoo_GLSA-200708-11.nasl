# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-11.xml
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
 script_id(25917);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200708-11");
 script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3948", "CVE-2007-3949", "CVE-2007-3950");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-11
(Lighttpd: Multiple vulnerabilities)


    Stefan Esser discovered errors with evidence of memory corruption in
    the code parsing the headers. Several independent researchers also
    reported errors involving the handling of HTTP headers, the mod_auth
    and mod_scgi modules, and the limitation of active connections.
  
Impact

    A remote attacker can trigger any of these vulnerabilities by sending
    malicious data to the server, which may lead to a crash or memory
    exhaustion, and potentially the execution of arbitrary code.
    Additionally, access-deny settings can be evaded by appending a final /
    to a URL.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.4.16"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3946');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3947');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3948');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3949');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3950');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-11] Lighttpd: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Lighttpd: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.4.16"), vulnerable: make_list("lt 1.4.16")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
