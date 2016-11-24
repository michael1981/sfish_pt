# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-27.xml
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
 script_id(14583);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200408-27");
 script_cve_id("CVE-2004-0500", "CVE-2004-0754", "CVE-2004-0784", "CVE-2004-0785");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-27
(Gaim: New vulnerabilities)


    Gaim fails to do proper bounds checking when:
    Handling MSN messages (partially fixed with GLSA 200408-12).
    Handling rich text format messages.
    Resolving local hostname.
    Receiving long URLs.
    Handling groupware messages.
    Allocating memory for webpages with fake content-length
    header.
    Furthermore Gaim fails to escape filenames when using drag and drop
    installation of smiley themes.
  
Impact

    These vulnerabilites could allow an attacker to crash Gaim or execute
    arbitrary code or commands with the permissions of the user running
    Gaim.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Gaim.
  
');
script_set_attribute(attribute:'solution', value: '
    All gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-0.81-r5"
    # emerge ">=net-im/gaim-0.81-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://gaim.sourceforge.net/security/index.php');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0500');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0754');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0784');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0785');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-27] Gaim: New vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: New vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 0.81-r5"), vulnerable: make_list("lt 0.81-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
