# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-16.xml
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
 script_id(14710);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-16");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-16
(Samba: Denial of Service vulnerabilities)


    There is a defect in smbd\'s ASN.1 parsing. A bad packet received during the
    authentication request could throw newly-spawned smbd processes into an
    infinite loop (CAN-2004-0807). Another defect was found in nmbd\'s
    processing of mailslot packets, where a bad NetBIOS request could crash the
    nmbd process (CAN-2004-0808).
  
Impact

    A remote attacker could send specially crafted packets to trigger both
    defects. The ASN.1 parsing issue can be exploited to exhaust all available
    memory on the Samba host, potentially denying all service to that server.
    The nmbd issue can be exploited to crash the nmbd process, resulting in a
    Denial of Service condition on the Samba server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba 3.x users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.7"
    # emerge ">=net-fs/samba-3.0.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0807');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0808');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-16] Samba: Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.7", "lt 3.0"), vulnerable: make_list("lt 3.0.7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
