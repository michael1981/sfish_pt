# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-25.xml
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
 script_id(23747);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-25");
 script_cve_id("CVE-2006-5779");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-25
(OpenLDAP: Denial of Service vulnerability)


    Evgeny Legerov has discovered that the truncation of an incoming
    authcid longer than 255 characters and ending with a space as the 255th
    character will lead to an improperly computed name length. This will
    trigger an assert in the libldap code.
  
Impact

    By sending a BIND request with a specially crafted authcid parameter to
    an OpenLDAP service, a remote attacker can cause the service to crash.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "net-nds/openldap"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5779');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-25] OpenLDAP: Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.3.27-r3", "rge 2.2.28-r5", "rge 2.1.30-r8"), vulnerable: make_list("lt 2.3.27-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
