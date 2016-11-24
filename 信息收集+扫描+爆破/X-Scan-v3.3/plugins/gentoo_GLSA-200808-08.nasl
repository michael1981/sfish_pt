# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200808-08.xml
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
 script_id(33854);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200808-08");
 script_cve_id("CVE-2008-2420");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200808-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200808-08
(stunnel: Security bypass)


    An unspecified bug in the OCSP search functionality of stunnel has been
    discovered.
  
Impact

    A remote attacker can use a revoked certificate that would be
    successfully authenticated by stunnel. This issue only concerns the
    users who have enabled the OCSP validation in stunnel.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All stunnel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/stunnel-4.24"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2420');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200808-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200808-08] stunnel: Security bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'stunnel: Security bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/stunnel", unaffected: make_list("ge 4.24", "lt 4"), vulnerable: make_list("lt 4.24")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
