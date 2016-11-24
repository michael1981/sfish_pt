# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-06.xml
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
 script_id(32208);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200805-06");
 script_cve_id("CVE-2008-1880");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-06
(Firebird: Data disclosure)


    Viesturs reported that the default configuration for Gentoo\'s init
    script ("/etc/conf.d/firebird") sets the "ISC_PASSWORD" environment
    variable when starting Firebird. It will be used when no password is
    supplied by a client connecting as the "SYSDBA" user.
  
Impact

    A remote attacker can authenticate as the "SYSDBA" user without
    providing the credentials, resulting in complete disclosure of all
    databases except for the user and password database (security2.fdb).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Firebird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/firebird-2.0.3.12981.0-r6"
    Note: /etc/conf.d is protected by Portage as a configuration directory.
    Do not forget to use "etc-update" or "dispatch-conf" to
    overwrite the "firebird" configuration file, and then restart Firebird.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1880');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-06] Firebird: Data disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Firebird: Data disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/firebird", unaffected: make_list("ge 2.0.3.12981.0-r6"), vulnerable: make_list("lt 2.0.3.12981.0-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
