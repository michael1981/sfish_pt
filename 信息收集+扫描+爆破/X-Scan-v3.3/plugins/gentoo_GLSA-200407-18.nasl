# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-18.xml
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
 script_id(14551);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200407-18");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-18
(mod_ssl: Format string vulnerability)


    A bug in ssl_engine_ext.c makes mod_ssl vulnerable to a ssl_log() related
    format string vulnerability in the mod_proxy hook functions.
  
Impact

    Given the right server configuration, an attacker could execute code as the
    user running Apache, usually "apache".
  
Workaround

    A server should not be vulnerable if it is not using both mod_ssl and
    mod_proxy. Otherwise there is no workaround other than to disable mod_ssl.
  
');
script_set_attribute(attribute:'solution', value: '
    All mod_ssl users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/mod_ssl-2.8.19"
    # emerge ">=net-www/mod_ssl-2.8.19"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://marc.theaimsgroup.com/?l=apache-modssl&m=109001100906749&w=2');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-18] mod_ssl: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mod_ssl: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.19"), vulnerable: make_list("le 2.8.18")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
