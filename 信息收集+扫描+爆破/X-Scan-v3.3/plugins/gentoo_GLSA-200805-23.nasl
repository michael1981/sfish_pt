# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-23.xml
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
 script_id(32491);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200805-23");
 script_cve_id("CVE-2008-1105");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-23
(Samba: Heap-based buffer overflow)


    Alin Rad Pop (Secunia Research) reported a vulnerability in Samba
    within the receive_smb_raw() function in the file lib/util_sock.c when
    parsing SMB packets, possibly leading to a heap-based buffer overflow
    via an overly large SMB packet.
  
Impact

    A remote attacker could possibly exploit this vulnerability by enticing
    a user to connect to a malicious server or by sending specially crafted
    packets to an nmbd server configured as a local or domain master
    browser, resulting in the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.28a-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1105');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-23] Samba: Heap-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.28a-r1"), vulnerable: make_list("lt 3.0.28a-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
