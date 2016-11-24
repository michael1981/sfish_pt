# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-17.xml
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
 script_id(22464);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200609-17");
 script_cve_id("CVE-2006-4924");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-17
(OpenSSH: Denial of Service)


    Tavis Ormandy of the Google Security Team discovered a Denial of
    Service vulnerability in the SSH protocol version 1 CRC compensation
    attack detector.
  
Impact

    A remote unauthenticated attacker may be able to trigger excessive CPU
    usage by sending a pathological SSH message, denying service to other
    legitimate users or processes.
  
Workaround

    The system administrator may disable SSH protocol version 1 in
    /etc/ssh/sshd_config.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openssh-4.3_p2-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4924');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-17] OpenSSH: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSH: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/openssh", unaffected: make_list("ge 4.3_p2-r5"), vulnerable: make_list("lt 4.3_p2-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
