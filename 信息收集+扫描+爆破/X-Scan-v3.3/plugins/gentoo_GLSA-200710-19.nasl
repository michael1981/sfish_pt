# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-19.xml
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
 script_id(27517);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-19");
 script_cve_id("CVE-2007-1536", "CVE-2007-2799");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-19
(The Sleuth Kit: Integer underflow)


    Jean-Sebastien Guay-Leroux reported an integer underflow in the
    file_printf() function of the "file" utility which is bundled with The
    Sleuth Kit (CVE-2007-1536, GLSA 200703-26). Note that Gentoo is not
    affected by the improper fix for this vulnerability (identified as
    CVE-2007-2799, see GLSA 200705-25) since version 4.20 of "file" was
    never shipped with The Sleuth Kit ebuilds.
  
Impact

    A remote attacker could entice a user to run The Sleuth Kit on a file
    system containing a specially crafted file that would trigger a
    heap-based buffer overflow possibly leading to the execution of
    arbitrary code with the rights of the user running The Sleuth Kit.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All The Sleuth Kit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-forensics/sleuthkit-2.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1536');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2799');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-26.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-25.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-19] The Sleuth Kit: Integer underflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'The Sleuth Kit: Integer underflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-forensics/sleuthkit", unaffected: make_list("ge 2.0.9"), vulnerable: make_list("lt 2.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
