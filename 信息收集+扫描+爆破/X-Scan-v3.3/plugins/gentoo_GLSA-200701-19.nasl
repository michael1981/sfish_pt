# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-19.xml
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
 script_id(24255);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-19");
 script_cve_id("CVE-2007-0476");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-19
(OpenLDAP: Insecure usage of /tmp during installation)


    Tavis Ormandy of the Gentoo Linux Security Team has discovered that the
    file gencert.sh distributed with the Gentoo ebuild for OpenLDAP does
    not exit upon the existence of a directory in /tmp during installation
    allowing for directory traversal.
  
Impact

    A local attacker could create a symbolic link in /tmp and potentially
    overwrite arbitrary system files upon a privileged user emerging
    OpenLDAP.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenLDAP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "net-nds/openldap"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0476');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-19] OpenLDAP: Insecure usage of /tmp during installation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenLDAP: Insecure usage of /tmp during installation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-nds/openldap", unaffected: make_list("ge 2.1.30-r10", "ge 2.2.28-r7", "ge 2.3.30-r2"), vulnerable: make_list("lt 2.1.30-r10", "lt 2.2.28-r7", "lt 2.3.30-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
