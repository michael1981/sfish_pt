# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-14.xml
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
 script_id(27049);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-14");
 script_cve_id("CVE-2007-4323");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-14
(DenyHosts: Denial of Service)


    Daniel B. Cid discovered that DenyHosts used an incomplete regular
    expression to parse failed login attempts, a different issue than GLSA
    200701-01.
  
Impact

    A remote unauthenticated attacker can add arbitrary hosts into the
    blacklist, including the "all" keyword, by submitting specially crafted
    version identification strings to the SSH server banner. An attacker
    may use this to prevent legitimate users from accessing a host
    remotely.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All DenyHosts users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/denyhosts-2.6-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4323');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-14] DenyHosts: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DenyHosts: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/denyhosts", unaffected: make_list("ge 2.6-r1"), vulnerable: make_list("lt 2.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
