# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-27.xml
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
 script_id(16418);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-27");
 script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-27
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier
    than 0.10.9, including:
    The COPS dissector could go into
    an infinite loop (CAN-2005-0006).
    The DLSw dissector could
    cause an assertion, making Ethereal exit prematurely
    (CAN-2005-0007).
    The DNP dissector could cause memory
    corruption (CAN-2005-0008).
    The Gnutella dissector could cause
    an assertion, making Ethereal exit prematurely (CAN-2005-0009).
    The MMSE dissector could free statically-allocated memory
    (CAN-2005-0010).
    The X11 dissector is vulnerable to a string
    buffer overflow (CAN-2005-0084).
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal, perform DoS by CPU and disk space utilization or even execute
    arbitrary code with the permissions of the user running Ethereal, which
    could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. However, it is strongly recommended to upgrade to
    the latest stable version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0006');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0007');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0008');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0009');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0010');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0084');
script_set_attribute(attribute: 'see_also', value: 'http://www.ethereal.com/news/item_20050120_01.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-27] Ethereal: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.9"), vulnerable: make_list("lt 0.10.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
