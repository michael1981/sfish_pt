# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-06.xml
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
 script_id(18232);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-06");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-06
(TCPDump: Decoding routines Denial of Service vulnerability)


    TCPDump improperly handles and decodes ISIS (CAN-2005-1278), BGP
    (CAN-2005-1267, CAN-2005-1279), LDP (CAN-2005-1279) and RSVP
    (CAN-2005-1280) packets. TCPDump might loop endlessly after receiving
    malformed packets.
  
Impact

    A malicious remote attacker can exploit the decoding issues for a
    Denial of Service attack by sending specially crafted packets, possibly
    causing TCPDump to loop endlessly.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All TCPDump users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/tcpdump-3.8.3-r3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1267');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1278');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1279');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1280');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-06] TCPDump: Decoding routines Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TCPDump: Decoding routines Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r3"), vulnerable: make_list("lt 3.8.3-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
