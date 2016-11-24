# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-04.xml
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
 script_id(14651);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200409-04");
 script_cve_id("CVE-2004-0832");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-04
(Squid: Denial of service when using NTLM authentication)


    Squid 2.5.x versions contain a bug in the functions ntlm_fetch_string()
    and ntlm_get_string() which lack checking the int32_t offset "o" for
    negative values.
  
Impact

    A remote attacker could cause a denial of service situation by sending
    certain malformed NTLMSSP packets if NTLM authentication is enabled.
  
Workaround

    Disable NTLM authentication by removing any "auth_param ntlm program
    ..." directives from squid.conf or use ntlm_auth from Samba-3.x.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-www/squid-2.5.6-r2"
    # emerge ">=net-www/squid-2.5.6-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www1.uk.squid-cache.org/squid/Versions/v2/2.5/bugs/#squid-2.5.STABLE6-ntlm_fetch_string');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0832');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-04] Squid: Denial of service when using NTLM authentication');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Denial of service when using NTLM authentication');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.6-r2", "lt 2.5"), vulnerable: make_list("le 2.5.6-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
