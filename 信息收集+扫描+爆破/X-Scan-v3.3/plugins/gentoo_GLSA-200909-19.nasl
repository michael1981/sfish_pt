# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-19.xml
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
 script_id(41023);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-19");
 script_cve_id("CVE-2009-2957", "CVE-2009-2958");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-19
(Dnsmasq: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in the TFTP functionality
    included in Dnsmasq:
    Pablo Jorge and Alberto Solino
    discovered a heap-based buffer overflow (CVE-2009-2957).
    An
    anonymous researcher reported a NULL pointer reference
    (CVE-2009-2958).
  
Impact

    A remote attacker in the local network could exploit these
    vulnerabilities by sending specially crafted TFTP requests to a machine
    running Dnsmasq, possibly resulting in the remote execution of
    arbitrary code with the privileges of the user running the daemon, or a
    Denial of Service. NOTE: The TFTP server is not enabled by default.
  
Workaround

    You can disable the TFTP server either at buildtime by not enabling the
    "tftp" USE flag, or at runtime. Make sure "--enable-tftp" is not set in
    the DNSMASQ_OPTS variable in the /etc/conf.d/dnsmasq file and
    "enable-tftp" is not set in /etc/dnsmasq.conf, either of which would
    enable TFTP support if it is compiled in.
  
');
script_set_attribute(attribute:'solution', value: '
    All Dnsmasq users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-dns/dnsmasq-2.5.0
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2957');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2958');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-19] Dnsmasq: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Dnsmasq: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/dnsmasq", unaffected: make_list("ge 2.5.0"), vulnerable: make_list("lt 2.5.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
