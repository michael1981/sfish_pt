# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-28.xml
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
 script_id(31634);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-28");
 script_cve_id("CVE-2007-5707", "CVE-2007-5708", "CVE-2008-0658");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-28
(OpenLDAP: Denial of Service vulnerabilities)


    The following errors have been discovered in OpenLDAP:
    Tony Blake discovered an error which exists within the normalisation of
    "objectClasses" (CVE-2007-5707).
    Thomas Sesselmann reported that, when running as a proxy-caching server
    the "add_filter_attrs()" function in servers/slapd/overlay/pcache.c
    does not correctly NULL terminate "new_attrs" (CVE-2007-5708).
    A double-free bug exists in attrs_free() in the file
    servers/slapd/back-bdb/modrdn.c, which was discovered by Jonathan
    Clarke (CVE-2008-0658).
  
Impact

    A remote attacker can cause a Denial of Serivce by sending a malformed
    "objectClasses" attribute, and via unknown vectors that prevent the
    "new_attrs" array from being NULL terminated, and via a modrdn
    operation with a NOOP (LDAP_X_NO_OPERATION) control.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-nds/openldap-2.3.41"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5707');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5708');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0658');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-28] OpenLDAP: Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP: Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.3.41"), vulnerable: make_list("lt 2.3.41")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
