# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-01.xml
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
 script_id(16392);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-01");
 script_cve_id("CVE-2004-1282");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-01
(LinPopUp: Buffer overflow in message reply)


    Stephen Dranger discovered that LinPopUp contains a buffer
    overflow in string.c, triggered when replying to a remote user message.
  
Impact

    A remote attacker could craft a malicious message that, when
    replied using LinPopUp, would exploit the buffer overflow. This would
    result in the execution of arbitrary code with the privileges of the
    user running LinPopUp.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LinPopUp users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/linpopup-2.0.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1282');
script_set_attribute(attribute: 'see_also', value: 'http://tigger.uic.edu/~jlongs2/holes/linpopup.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-01] LinPopUp: Buffer overflow in message reply');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LinPopUp: Buffer overflow in message reply');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/linpopup", unaffected: make_list("ge 2.0.4-r1"), vulnerable: make_list("lt 2.0.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
