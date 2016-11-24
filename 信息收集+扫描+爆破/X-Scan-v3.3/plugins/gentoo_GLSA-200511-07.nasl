# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-07.xml
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
 script_id(20157);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-07");
 script_cve_id("CVE-2005-3393", "CVE-2005-3409");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-07
(OpenVPN: Multiple vulnerabilities)


    The OpenVPN client contains a format string bug in the handling of
    the foreign_option in options.c. Furthermore, when the OpenVPN server
    runs in TCP mode, it may dereference a NULL pointer under specific
    error conditions.
  
Impact

    A remote attacker could setup a malicious OpenVPN server and trick
    the user into connecting to it, potentially executing arbitrary code on
    the client\'s computer. A remote attacker could also exploit the NULL
    dereference issue by sending specific packets to an OpenVPN server
    running in TCP mode, resulting in a Denial of Service condition.
  
Workaround

    Do not use "pull" or "client" options in the OpenVPN client
    configuration file, and use UDP mode for the OpenVPN server.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenVPN users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openvpn-2.0.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3393');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3409');
script_set_attribute(attribute: 'see_also', value: 'http://openvpn.net/changelog.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-07] OpenVPN: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenVPN: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/openvpn", unaffected: make_list("ge 2.0.4"), vulnerable: make_list("lt 2.0.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
