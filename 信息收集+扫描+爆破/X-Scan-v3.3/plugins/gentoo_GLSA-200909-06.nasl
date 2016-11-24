# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-06.xml
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
 script_id(40914);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-06");
 script_cve_id("CVE-2009-1440");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-06
(aMule: Parameter injection)


    Sam Hocevar discovered that the aMule preview function does not
    properly sanitize file names.
  
Impact

    A remote attacker could entice a user to download a file with a
    specially crafted file name to inject arbitrary arguments to the
    victim\'s video player.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All aMule users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-p2p/amule-2.2.5
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1440');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-06] aMule: Parameter injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'aMule: Parameter injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/amule", unaffected: make_list("ge 2.2.5"), vulnerable: make_list("lt 2.2.5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
