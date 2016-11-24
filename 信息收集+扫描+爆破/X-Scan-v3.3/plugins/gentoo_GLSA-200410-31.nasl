# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-31.xml
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
 script_id(15587);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-31");
 script_cve_id("CVE-2004-1096");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-31 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-31
(Archive::Zip: Virus detection evasion)


    Archive::Zip can be used by email scanning software (like amavisd-new)
    to uncompress attachments before virus scanning. By modifying the
    uncompressed size of archived files in the global header of the ZIP
    file, it is possible to fool Archive::Zip into thinking some files
    inside the archive have zero length.
  
Impact

    An attacker could send a carefully crafted ZIP archive containing a
    virus file and evade detection on some email virus-scanning software
    relying on Archive::Zip for decompression.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Archive::Zip users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/Archive-Zip-1.14"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=153');
script_set_attribute(attribute: 'see_also', value: 'http://rt.cpan.org/NoAuth/Bug.html?id=8077');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1096');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-31.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-31] Archive::Zip: Virus detection evasion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Archive::Zip: Virus detection evasion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-perl/Archive-Zip", unaffected: make_list("ge 1.14"), vulnerable: make_list("lt 1.14")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
