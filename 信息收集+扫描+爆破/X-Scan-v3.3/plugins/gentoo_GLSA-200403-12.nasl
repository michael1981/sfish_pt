# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-12.xml
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
 script_id(14463);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-12");
 script_cve_id("CVE-2003-1201");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-12
(OpenLDAP DoS Vulnerability)


    A password extended operation (password EXOP) which fails will cause
    the slapd server to free() an uninitialized pointer, possibly resulting
    in a segfault. This only affects servers using the back-ldbm backend.
    Such a crash is not guaranteed with every failed operation, however, it
    is possible.
  
Impact

    An attacker (or indeed, a normal user) may crash the OpenLDAP server,
    creating a Denial of Service condition.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    OpenLDAP users should upgrade to version 2.1.13 or later:
    # emerge sync
    # emerge -pv ">=net-nds/openldap-2.1.13"
    # emerge ">=net-nds/openldap-2.1.13"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.openldap.org/its/index.cgi?findid=2390');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1201');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-12] OpenLDAP DoS Vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP DoS Vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.1.13"), vulnerable: make_list("le 2.1.12")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
