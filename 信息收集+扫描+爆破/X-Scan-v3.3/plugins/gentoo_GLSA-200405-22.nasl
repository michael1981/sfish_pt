# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-22.xml
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
 script_id(14508);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200405-22");
 script_cve_id("CVE-2003-0993", "CVE-2003-0020", "CVE-2003-0987", "CVE-2004-0174");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-22
(Apache 1.3: Multiple vulnerabilities)


    On 64-bit big-endian platforms, mod_access does not properly parse
    Allow/Deny rules using IP addresses without a netmask which could result in
    failure to match certain IP addresses.
    Terminal escape sequences are not filtered from error logs. This could be
    used by an attacker to insert escape sequences into a terminal emulater
    vulnerable to escape sequences.
    mod_digest does not properly verify the nonce of a client response by using
    a AuthNonce secret. This could permit an attacker to replay the response of
    another website. This does not affect mod_auth_digest.
    On certain platforms there is a starvation issue where listening sockets
    fails to handle short-lived connection on a rarely-accessed listening
    socket. This causes the child to hold the accept mutex and block out new
    connections until another connection arrives on the same rarely-accessed
    listening socket thus leading to a denial of service.
  
Impact

    These vulnerabilities could lead to attackers bypassing intended access
    restrictions, denial of service, and possibly execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest stable version of Apache 1.3.
    # emerge sync
    # emerge -pv ">=www-servers/apache-1.3.31"
    # emerge ">=www-servers/apache-1.3.31"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0993');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0020');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2003-0987');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0174');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-22] Apache 1.3: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 1.3.31"), vulnerable: make_list("lt 1.3.31")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
