# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-25.xml
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
 script_id(14780);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-25");
 script_cve_id("CVE-2004-0558");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-25
(CUPS: Denial of service vulnerability)


    Alvaro Martinez Echevarria discovered a hole in the CUPS Internet Printing
    Protocol (IPP) implementation that allows remote attackers to cause CUPS to
    stop listening on the IPP port.
  
Impact

    A remote user with malicious intent can easily cause a denial of service to
    the CUPS daemon by sending a specially-crafted UDP datagram packet to the
    IPP port.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-print/cups-1.1.20-r2"
    # emerge ">=net-print/cups-1.1.20-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.cups.org/str.php?L863');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0558');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-25] CUPS: Denial of service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Denial of service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.20-r2"), vulnerable: make_list("lt 1.1.20-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
