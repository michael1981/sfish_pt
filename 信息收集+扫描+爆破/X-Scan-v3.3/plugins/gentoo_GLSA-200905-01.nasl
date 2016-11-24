# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200905-01.xml
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
 script_id(38677);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200905-01");
 script_cve_id("CVE-2008-1897", "CVE-2008-2119", "CVE-2008-3263", "CVE-2008-3264", "CVE-2008-3903", "CVE-2008-5558", "CVE-2009-0041");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200905-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200905-01
(Asterisk: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in the IAX2 channel
    driver when performing the 3-way handshake (CVE-2008-1897), when
    handling a large number of POKE requests (CVE-2008-3263), when handling
    authentication attempts (CVE-2008-5558) and when handling firmware
    download (FWDOWNL) requests (CVE-2008-3264). Asterisk does also not
    correctly handle SIP INVITE messages that lack a "From" header
    (CVE-2008-2119), and responds differently to a failed login attempt
    depending on whether the user account exists (CVE-2008-3903,
    CVE-2009-0041).
  
Impact

    Remote unauthenticated attackers could send specially crafted data to
    Asterisk, possibly resulting in a Denial of Service via a daemon crash,
    call-number exhaustion, CPU or traffic consumption. Remote
    unauthenticated attackers could furthermore enumerate valid usernames
    to facilitate brute force login attempts.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/asterisk-1.2.32"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1897');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2119');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3263');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3264');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3903');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5558');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0041');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200905-01] Asterisk: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("ge 1.2.32"), vulnerable: make_list("lt 1.2.32")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
