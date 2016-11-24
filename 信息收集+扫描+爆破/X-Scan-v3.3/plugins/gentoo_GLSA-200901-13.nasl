# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-13.xml
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
 script_id(35432);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200901-13");
 script_cve_id("CVE-2008-2927", "CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-13
(Pidgin: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Pidgin and the
    libpurple library:
    A participant to the TippingPoint ZDI reported multiple integer
    overflows in the msn_slplink_process_msg() function in the MSN protocol
    implementation (CVE-2008-2927).
    Juan Pablo Lopez Yacubian is credited for reporting a use-after-free
    flaw in msn_slplink_process_msg() in the MSN protocol implementation
    (CVE-2008-2955).
    The included UPnP server does not limit the size of data to be
    downloaded for UPnP service discovery, according to a report by Andrew
    Hunt and Christian Grothoff (CVE-2008-2957).
    Josh Triplett discovered that the NSS plugin for libpurple does not
    properly verify SSL certificates (CVE-2008-3532).
  
Impact

    A remote attacker could send specially crafted messages or files using
    the MSN protocol which could result in the execution of arbitrary code
    or crash Pidgin. NOTE: Successful exploitation might require the
    victim\'s interaction. Furthermore, an attacker could conduct
    man-in-the-middle attacks to obtain sensitive information using bad
    certificates and cause memory and disk resources to exhaust.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pidgin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/pidgin-2.5.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2927');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2955');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2957');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3532');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-13] Pidgin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pidgin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/pidgin", unaffected: make_list("ge 2.5.1"), vulnerable: make_list("lt 2.5.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
