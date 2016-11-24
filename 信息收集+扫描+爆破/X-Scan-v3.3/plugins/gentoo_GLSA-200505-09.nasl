# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-09.xml
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
 script_id(18252);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-09");
 script_cve_id("CVE-2005-1261", "CVE-2005-1262");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-09
(Gaim: Denial of Service and buffer overflow vulnerabilties)


    Stu Tomlinson discovered that Gaim is vulnerable to a remote stack
    based buffer overflow when receiving messages in certain protocols,
    like Jabber and SILC, with a very long URL (CAN-2005-1261). Siebe
    Tolsma discovered that Gaim is also vulnerable to a remote Denial of
    Service attack when receiving a specially crafted MSN message
    (CAN-2005-1262).
  
Impact

    A remote attacker could cause a buffer overflow by sending an
    instant message with a very long URL, potentially leading to the
    execution of malicious code. By sending a SLP message with an empty
    body, a remote attacker could cause a Denial of Service or crash of the
    Gaim client.
  
Workaround

    There are no known workarounds at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.3.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1261');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1262');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-09] Gaim: Denial of Service and buffer overflow vulnerabilties');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Denial of Service and buffer overflow vulnerabilties');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.3.0"), vulnerable: make_list("lt 1.3.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
