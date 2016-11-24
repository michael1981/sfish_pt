# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200910-02.xml
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
 script_id(42214);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200910-02");
 script_cve_id("CVE-2009-1376", "CVE-2009-1889", "CVE-2009-2694", "CVE-2009-3026");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200910-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200910-02
(Pidgin: Multiple vulnerabilities)


    Multiple vulnerabilities were found in Pidgin:
    Yuriy
    Kaminskiy reported that the OSCAR protocol implementation in Pidgin
    misinterprets the ICQWebMessage message type as the ICQSMS message
    type, triggering an allocation of a large amount of memory
    (CVE-2009-1889).
    Federico Muttis of Core Security Technologies
    reported that the msn_slplink_process_msg() function in
    libpurple/protocols/msn/slplink.c in libpurple as used in Pidgin
    doesn\'t properly process incoming SLP messages, triggering an overwrite
    of an arbitrary memory location (CVE-2009-2694). NOTE: This issue
    reportedly exists because of an incomplete fix for CVE-2009-1376 (GLSA
    200905-07).
    bugdave reported that protocols/jabber/auth.c in
    libpurple as used in Pidgin does not follow the "require TSL/SSL"
    preference when connecting to older Jabber servers that do not follow
    the XMPP specification, resulting in a connection to the server without
    the expected encryption (CVE-2009-3026).
  
Impact

    A remote attacker could send specially crafted SLP (via MSN) or ICQ web
    messages, possibly leading to execution of arbitrary code with the
    privileges of the user running Pidgin, unauthorized information
    disclosure, or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-im/pidgin-2.5.9-r1
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1376');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1889');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2694');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3026');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200905-07.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200910-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200910-02] Pidgin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pidgin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/pidgin", unaffected: make_list("ge 2.5.9-r1"), vulnerable: make_list("lt 2.5.9-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
