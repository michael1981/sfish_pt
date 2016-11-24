# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-15.xml
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
 script_id(21579);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200605-15");
 script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-15
(Quagga Routing Suite: Multiple vulnerabilities)


    Konstantin V. Gavrilenko discovered two flaws in the Routing
    Information Protocol (RIP) daemon that allow the processing of RIP v1
    packets (carrying no authentication) even when the daemon is configured
    to use MD5 authentication or, in another case, even if RIP v1 is
    completely disabled. Additionally, Fredrik Widell reported that the
    Border Gateway Protocol (BGP) daemon contains a flaw that makes it lock
    up and use all available CPU when a specific command is issued from the
    telnet interface.
  
Impact

    By sending RIP v1 response packets, an unauthenticated attacker
    can alter the routing table of a router running Quagga\'s RIP daemon and
    disclose routing information. Additionally, it is possible to lock up
    the BGP daemon from the telnet interface.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Quagga users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/quagga-0.98.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2223');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2224');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2276');
script_set_attribute(attribute: 'see_also', value: 'http://www.quagga.net/news2.php?y=2006&m=5&d=8#id1147115280');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-15] Quagga Routing Suite: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Quagga Routing Suite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/quagga", unaffected: make_list("ge 0.98.6-r1"), vulnerable: make_list("lt 0.98.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
