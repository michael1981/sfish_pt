# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-25.xml
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
 script_id(14581);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-25");
 script_cve_id("CVE-2004-1462", "CVE-2004-1463");
 script_xref(name: "OSVDB", value: "8194");
 script_xref(name: "OSVDB", value: "8195");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-25
(MoinMoin: Group ACL bypass)


    MoinMoin contains two unspecified bugs, one allowing anonymous users
    elevated access when not using ACLs, and the other in the ACL handling
    in the PageEditor.
  
Impact

    Restrictions on anonymous users were not properly enforced. This could
    lead to unauthorized users gaining administrative access to functions
    such as "revert" and "delete". Sites are vulnerable whether or not they
    are using ACLs.
  
Workaround

    There is no known workaround.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of MoinMoin,
    as follows:
    # emerge sync
    # emerge -pv ">=www-apps/moinmoin-1.2.3"
    # emerge ">=www-apps/moinmoin-1.2.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'https://sourceforge.net/project/shownotes.php?group_id=8482&release_id=254801');
script_set_attribute(attribute: 'see_also', value: 'http://www.osvdb.org/displayvuln.php?osvdb_id=8194');
script_set_attribute(attribute: 'see_also', value: 'http://www.osvdb.org/displayvuln.php?osvdb_id=8195');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1462');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1463');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-25] MoinMoin: Group ACL bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MoinMoin: Group ACL bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/moinmoin", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("le 1.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
