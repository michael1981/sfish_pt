# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-15.xml
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
 script_id(35107);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-15");
 script_cve_id("CVE-2004-0768", "CVE-2006-0481", "CVE-2006-3334", "CVE-2008-1382", "CVE-2008-3964");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-15
(POV-Ray: User-assisted execution of arbitrary code)


    POV-Ray uses a statically linked copy of libpng to view and output PNG
    files. The version shipped with POV-Ray is vulnerable to CVE-2008-3964,
    CVE-2008-1382, CVE-2006-3334, CVE-2006-0481, CVE-2004-0768. A bug in
    POV-Ray\'s build system caused it to load the old version when your
    installed copy of libpng was >=media-libs/libpng-1.2.10.
  
Impact

    An attacker could entice a user to load a specially crafted PNG file as
    a texture, resulting in the execution of arbitrary code with the
    permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All POV-Ray users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/povray-3.6.1-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0768');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0481');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3334');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1382');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3964');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-15] POV-Ray: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'POV-Ray: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/povray", unaffected: make_list("ge 3.6.1-r4"), vulnerable: make_list("lt 3.6.1-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
