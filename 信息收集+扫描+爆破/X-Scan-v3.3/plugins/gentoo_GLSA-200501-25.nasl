# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-25.xml
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
 script_id(16416);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-25");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0194");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-25
(Squid: Multiple vulnerabilities)


    Squid contains a vulnerability in the gopherToHTML function
    (CAN-2005-0094) and incorrectly checks the \'number of caches\' field
    when parsing WCCP_I_SEE_YOU messages (CAN-2005-0095). Furthermore the
    NTLM code contains two errors. One is a memory leak in the
    fakeauth_auth helper (CAN-2005-0096) and the other is a NULL pointer
    dereferencing error (CAN-2005-0097). Finally Squid also contains an
    error in the ACL parsing code (CAN-2005-0194).
  
Impact

    With the WCCP issue an attacker could cause denial of service by
    sending a specially crafted UDP packet. With the Gopher issue an
    attacker might be able to execute arbitrary code by enticing a user to
    connect to a malicious Gopher server. The NTLM issues could lead to
    denial of service by memory consumption or by crashing Squid. The ACL
    issue could lead to ACL bypass.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/squid-2.5.7-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13825/');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13789/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0094');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0095');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0096');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0097');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0194');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-25] Squid: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.7-r2"), vulnerable: make_list("lt 2.5.7-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
