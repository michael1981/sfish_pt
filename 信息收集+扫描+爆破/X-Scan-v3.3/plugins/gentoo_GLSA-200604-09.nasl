# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-09.xml
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
 script_id(21255);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200604-09");
 script_cve_id("CVE-2006-1721");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200604-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200604-09
(Cyrus-SASL: DIGEST-MD5 Pre-Authentication Denial of Service)


    Cyrus-SASL contains an unspecified vulnerability in the DIGEST-MD5
    process that could lead to a Denial of Service.
  
Impact

    An attacker could possibly exploit this vulnerability by sending
    specially crafted data stream to the Cyrus-SASL server, resulting in a
    Denial of Service even if the attacker is not able to authenticate.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cyrus-SASL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/cyrus-sasl-2.1.21-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1721');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200604-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200604-09] Cyrus-SASL: DIGEST-MD5 Pre-Authentication Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus-SASL: DIGEST-MD5 Pre-Authentication Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/cyrus-sasl", unaffected: make_list("ge 2.1.21-r2"), vulnerable: make_list("lt 2.1.21-r2")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
