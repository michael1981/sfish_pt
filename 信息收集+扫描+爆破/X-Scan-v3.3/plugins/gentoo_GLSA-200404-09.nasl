# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-09.xml
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
 script_id(14474);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200404-09");
 script_cve_id("CVE-2004-0371");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-09
(Cross-realm trust vulnerability in Heimdal)


    Heimdal does not properly perform certain consistency checks for
    cross-realm requests, which allows remote attackers with control of a realm
    to impersonate others in the cross-realm trust path.
  
Impact

    Remote attackers with control of a realm may be able to impersonate other
    users in the cross-realm trust path.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Heimdal users should upgrade to version 0.6.1 or later:
    # emerge sync
    # emerge -pv ">=app-crypt/heimdal-0.6.1"
    # emerge ">=app-crypt/heimdal-0.6.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0371');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-09] Cross-realm trust vulnerability in Heimdal');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cross-realm trust vulnerability in Heimdal');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/heimdal", unaffected: make_list("ge 0.6.1"), vulnerable: make_list("le 0.6.0")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
