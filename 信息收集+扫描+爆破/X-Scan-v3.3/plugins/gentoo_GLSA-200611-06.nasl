# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-06.xml
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
 script_id(23671);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200611-06");
 script_cve_id("CVE-2006-5051", "CVE-2006-5052");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-06
(OpenSSH: Multiple Denial of Service vulnerabilities)


    Tavis Ormandy of the Google Security Team has discovered a
    pre-authentication vulnerability, causing sshd to spin until the login
    grace time has been expired. Mark Dowd found an unsafe signal handler
    that was vulnerable to a race condition. It has also been discovered
    that when GSSAPI authentication is enabled, GSSAPI will in certain
    cases incorrectly abort.
  
Impact

    The pre-authentication and signal handler vulnerabilities can cause a
    Denial of Service in OpenSSH. The vulnerability in the GSSAPI
    authentication abort could be used to determine the validity of
    usernames on some platforms.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openssh-4.4_p1-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5051');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5052');
script_set_attribute(attribute: 'see_also', value: 'http://www.openssh.com/txt/release-4.4');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-06] OpenSSH: Multiple Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSH: Multiple Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/openssh", unaffected: make_list("ge 4.4_p1-r5"), vulnerable: make_list("lt 4.4_p1-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
