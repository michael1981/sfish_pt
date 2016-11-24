# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-29.xml
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
 script_id(32075);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-29");
 script_cve_id("CVE-2008-1568", "CVE-2008-1796");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-29
(Comix: Multiple vulnerabilities)


    Comix does not properly sanitize filenames containing shell
    metacharacters when they are passed to the rar, unrar, or jpegtran
    programs (CVE-2008-1568). Comix also creates directories with
    predictable names (CVE-2008-1796).
  
Impact

    A remote attacker could exploit the first vulnerability by enticing a
    user to use Comix to open a file with a specially crafted filename,
    resulting in the execution of arbitrary commands. The second
    vulnerability could be exploited by a local attacker to cause a Denial
    of Service by creating a file or directory with the same filename as
    the predictable filename used by Comix.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Comix users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/comix-3.6.4-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1568');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1796');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-29] Comix: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Comix: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/comix", unaffected: make_list("ge 3.6.4-r1"), vulnerable: make_list("lt 3.6.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
