# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-05.xml
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
 script_id(40913);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-05");
 script_cve_id("CVE-2009-0790", "CVE-2009-2185");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-05
(Openswan: Denial of Service)


    Multiple vulnerabilities have been discovered in Openswan:
    Gerd v. Egidy reported a NULL pointer dereference in the Dead Peer
    Detection of the pluto IKE daemon as included in Openswan
    (CVE-2009-0790).
    The Orange Labs vulnerability research team
    discovered multiple vulnerabilities in the ASN.1 parser
    (CVE-2009-2185).
  
Impact

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted R_U_THERE or R_U_THERE_ACK packets, or a specially
    crafted X.509 certificate containing a malicious Relative Distinguished
    Name (RDN), UTCTIME string or GENERALIZEDTIME string to cause a Denial
    of Service of the pluto IKE daemon.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Openswan users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-misc/openswan-2.4.15
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0790');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2185');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-05] Openswan: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Openswan: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/openswan", unaffected: make_list("ge 2.4.15"), vulnerable: make_list("lt 2.4.15")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
